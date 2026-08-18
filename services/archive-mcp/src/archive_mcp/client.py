from __future__ import annotations

import asyncio
import hashlib
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import safe_relative_destination, safe_segment, stable_id

from .config import RuntimeConfig
from .licenses import LicenseVerdict, classify_item
from .matcher import (
    LOSSLESS_EXTENSIONS,
    candidate_id_for,
    coerce_list,
    extract_search_docs,
    score_candidate,
    select_album_files,
)
from .models import AlbumCandidate, ArchiveFile, DownloadBatch
from .repository import BatchRepository

# How often one file is fetched again before the album counts as lost. The
# Archive serves from rotating node hosts, so a single 5xx is not a verdict.
MAX_FILE_RETRIES = 2
SEARCH_FIELDS = (
    "identifier",
    "title",
    "creator",
    "licenseurl",
    "rights",
    "collection",
    "mediatype",
    "year",
    "downloads",
)


class ArchiveError(RuntimeError):
    pass


def deterministic_batch_id(candidate_id: str, external_id: str | None = None) -> str:
    operation_key = external_id or stable_id("album", candidate_id)
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"flowoox:archive:{operation_key}:{candidate_id}",
        )
    )


def sanitize_destination(value: str) -> str:
    raw = (value or "").strip().replace("\\", "/")
    if not raw or raw.startswith("/"):
        raise ValueError("Destination must be a non-empty relative path")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Destination contains an invalid path segment")
    parts = [safe_segment(part) for part in path.parts]
    if not parts:
        raise ValueError("Destination is empty after sanitization")
    return "/".join(parts)


def local_file_name(file: ArchiveFile, taken: set[str]) -> str:
    """The name one Archive file gets inside the destination folder.

    The remote name is kept, because the importer reads a track number out of
    the file name and the Archive's own names usually carry one. Only the
    characters that cannot live on the target filesystem are replaced — the
    Archive keeps things like ``¿`` where the uploader meant ``?``. Files may
    also sit in a subdirectory of an item; those are flattened, so a collision
    has to be resolved rather than silently overwriting a track.
    """
    posix = PurePosixPath(file.name)
    stem = safe_segment(posix.stem, fallback="track")
    extension = posix.suffix.lower()
    name = f"{stem}{extension}"
    if name.casefold() not in taken:
        return name
    marker = f"{file.disc or 1}-{file.track:02d}" if file.track else stable_id(file.name, length=6)
    return f"{stem} ({marker}){extension}"


class ArchiveClient:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        batches: BatchRepository | None = None,
        downloads_dir: Path = Path("/downloads"),
        tasks: dict[str, asyncio.Task[None]] | None = None,
    ):
        self.config = config
        self.batches = batches
        self.downloads_dir = downloads_dir
        # Downloads outlive the tool call that started them, so the tasks have
        # to be held somewhere; a local variable would let them be collected
        # mid-transfer.
        self.tasks = tasks if tasks is not None else {}

    @property
    def headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "User-Agent": self.config.user_agent}

    async def request_json(
        self, path: str, *, params: dict[str, Any] | list[tuple[str, Any]] | None = None
    ) -> Any:
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            timeout=self.config.search_timeout + 15,
            follow_redirects=True,
        ) as client:
            response = await client.get(path, params=params)
        if response.status_code >= 400:
            raise ArchiveError(
                f"archive.org GET {path} failed ({response.status_code}): "
                f"{response.text[:800]}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ArchiveError(
                f"archive.org GET {path} returned no JSON: {response.text[:300]}"
            ) from exc

    async def health(self) -> dict[str, Any]:
        """Reachability plus proof that the search index actually answers."""
        payload = await self.search_raw("mediatype:audio", rows=1)
        found = int(
            get_case_insensitive(
                get_case_insensitive(payload, "response", default={}),
                "numFound",
                default=0,
            )
            or 0
        )
        if found <= 0:
            raise ArchiveError(
                "archive.org ist erreichbar, liefert aber keine Audio-Treffer. "
                "Das deutet auf einen Ausfall der Suchindexe hin."
            )
        return {
            "ok": True,
            "base_url": self.config.base_url,
            "audio_items_indexed": found,
            "logged_in": True,
            "warnings": [],
            "lossless_only": self.config.lossless_only,
            "minimum_lossy_bitrate_kbps": self.config.minimum_lossy_bitrate_kbps,
        }

    async def search_raw(self, query: str, *, rows: int) -> Any:
        params: list[tuple[str, Any]] = [
            ("q", query),
            ("rows", str(max(1, rows))),
            ("page", "1"),
            ("output", "json"),
        ]
        params.extend(("fl[]", field) for field in SEARCH_FIELDS)
        return await self.request_json("/advancedsearch.php", params=params)

    async def get_metadata(self, identifier: str) -> dict[str, Any]:
        """Full item metadata, or an empty dict when the item does not exist.

        A missing item answers **HTTP 200 with an empty JSON object**, not 404.
        Treating the status code as the answer would turn every typo into a
        candidate with no files.
        """
        payload = await self.request_json(f"/metadata/{quote(identifier, safe='')}")
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _quote_phrase(value: str) -> str:
        return '"' + str(value or "").replace('"', " ").strip() + '"'

    def query_ladder(self, artist: str, album: str, search_text: str | None) -> list[str]:
        """Queries from precise to broad.

        Measured on the live index: the fielded form
        ``creator:(...) AND title:(...)`` returned 2 hits for a known album
        while the same words as free text returned 10, eight of them podcasts.
        The broad forms are only reached when the precise one finds nothing.
        """
        if search_text:
            return [f"mediatype:audio AND ({search_text})"]
        artist_phrase = self._quote_phrase(artist)
        album_phrase = self._quote_phrase(album)
        ladder = [
            f"mediatype:audio AND creator:({artist_phrase}) AND title:({album_phrase})",
            f"mediatype:audio AND creator:({artist_phrase})",
            f"mediatype:audio AND title:({album_phrase}) AND {artist_phrase}",
        ]
        return [query for index, query in enumerate(ladder) if query not in ladder[:index]]

    async def search_album(
        self,
        *,
        artist: str,
        album: str,
        expected_track_count: int | None = None,
        max_candidates: int = 10,
        lossless_only: bool | None = None,
        minimum_lossy_bitrate_kbps: int | None = None,
        search_text: str | None = None,
    ) -> tuple[str, list[AlbumCandidate], dict[str, Any]]:
        effective_lossless = (
            self.config.lossless_only if lossless_only is None else lossless_only
        )
        effective_bitrate = (
            self.config.minimum_lossy_bitrate_kbps
            if minimum_lossy_bitrate_kbps is None
            else minimum_lossy_bitrate_kbps
        )
        search_id = stable_id("archive-search", artist, album, search_text or "")
        rejected: list[str] = []
        docs: list[dict[str, Any]] = []
        used_query = ""
        for query in self.query_ladder(artist, album, search_text):
            used_query = query
            payload = await self.search_raw(query, rows=self.config.result_limit)
            docs = extract_search_docs(payload)
            if docs:
                break

        candidates: list[AlbumCandidate] = []
        probed = 0
        for doc in docs:
            if probed >= self.config.metadata_probe_limit:
                break
            identifier = str(get_case_insensitive(doc, "identifier", default="") or "")
            if not identifier:
                continue
            probed += 1
            try:
                metadata = await self.get_metadata(identifier)
            except ArchiveError as exc:
                rejected.append(f"{identifier}: Metadaten nicht lesbar ({exc})")
                continue
            candidate, reason = self.build_candidate(
                identifier=identifier,
                metadata=metadata,
                artist=artist,
                album=album,
                search_id=search_id,
                expected_track_count=expected_track_count,
                lossless_only=effective_lossless,
                minimum_lossy_bitrate_kbps=effective_bitrate,
            )
            if candidate is None:
                rejected.append(f"{identifier}: {reason}")
                continue
            candidates.append(candidate)

        candidates.sort(key=lambda item: item.score, reverse=True)
        stats = {
            "responses": len(docs),
            "items_probed": probed,
            "rejected": rejected,
            "lossless_only": effective_lossless,
            "minimum_lossy_bitrate_kbps": effective_bitrate,
            "search_text": used_query,
        }
        return search_id, candidates[:max_candidates], stats

    def build_candidate(
        self,
        *,
        identifier: str,
        metadata: dict[str, Any],
        artist: str,
        album: str,
        search_id: str,
        expected_track_count: int | None,
        lossless_only: bool,
        minimum_lossy_bitrate_kbps: int,
    ) -> tuple[AlbumCandidate | None, str]:
        if not metadata:
            return None, "Item existiert nicht (leere Metadaten trotz HTTP 200)"
        item = get_case_insensitive(metadata, "metadata", default={})
        if not isinstance(item, dict):
            return None, "Item hat keinen Metadatenblock"

        verdict: LicenseVerdict = classify_item(item)
        if not verdict.redistributable:
            return None, verdict.reason

        records = get_case_insensitive(metadata, "files", default=[])
        records = [record for record in records if isinstance(record, dict)]
        files, dropped = select_album_files(
            records,
            preferred_formats=self.config.preferred_formats,
            lossless_only=lossless_only,
            minimum_lossy_bitrate_kbps=minimum_lossy_bitrate_kbps,
        )
        if not files:
            detail = f" ({dropped[0]})" if dropped else ""
            return None, f"Keine Audiodatei hat den Qualitätsfilter passiert{detail}"
        if len(files) < self.config.minimum_tracks:
            return None, f"Nur {len(files)} Titel, verlangt sind {self.config.minimum_tracks}"

        item_title = str(get_case_insensitive(item, "title", default="") or "")
        creators = coerce_list(get_case_insensitive(item, "creator", "artist"))
        item_creator = creators[0] if creators else ""
        if not item_creator:
            # Measured: netlabel items routinely leave the item-level creator
            # empty and name the artist only on each file. Scoring against an
            # empty string would reject them for having no artist at all.
            item_creator = next(
                (
                    str(get_case_insensitive(record, "creator", "artist", default="") or "")
                    for record in records
                    if get_case_insensitive(record, "creator", "artist")
                ),
                "",
            )
        score, reasons = score_candidate(
            artist=artist,
            album=album,
            item_title=item_title,
            item_creator=item_creator,
            files=files,
            expected_track_count=expected_track_count,
            verdict=verdict,
        )
        reasons.append(verdict.label or verdict.basis)
        return (
            AlbumCandidate(
                candidate_id=candidate_id_for(identifier, files),
                search_id=search_id,
                identifier=identifier,
                folder=identifier,
                artist=item_creator or artist,
                album=item_title or album,
                files=files,
                audio_file_count=len(files),
                total_file_count=len(records),
                disc_count=len({file.disc or 1 for file in files}) or 1,
                formats=sorted({file.extension for file in files}),
                total_bytes=sum(file.size for file in files),
                license_url=verdict.url,
                license_label=verdict.label,
                rights_basis=verdict.basis,
                collections=coerce_list(get_case_insensitive(item, "collection")),
                detail_url=f"{self.config.base_url}/details/{identifier}",
                score=score,
                score_reasons=reasons,
            ),
            "",
        )

    # ------------------------------------------------------------------ queue

    async def get_existing_operation_batch(
        self,
        *,
        candidate_id: str,
        external_id: str | None = None,
        destination: str | None = None,
    ) -> dict[str, Any] | None:
        requested_id = deterministic_batch_id(candidate_id, external_id)
        if self.batches is None:
            return None
        if self.batches.get(requested_id) is None:
            return None
        output = self.get_batch(requested_id)
        if destination:
            output.setdefault("artifact_path", sanitize_destination(destination))
        output["idempotent"] = True
        return output

    async def queue_candidate(
        self,
        candidate: AlbumCandidate,
        *,
        destination: str | None = None,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        """Record the album and start fetching it in the background.

        The Archive has no queue: "queueing" is this connector starting the
        transfers itself. The tool call returns as soon as the record exists so
        the orchestrator can poll, exactly as it does for Soulseek.
        """
        destination = (
            sanitize_destination(destination)
            if destination
            else safe_relative_destination(candidate.artist, candidate.album)
        )
        existing = await self.get_existing_operation_batch(
            candidate_id=candidate.candidate_id,
            external_id=external_id,
            destination=destination,
        )
        if existing is not None:
            return existing

        operation_key = external_id or stable_id("album", candidate.candidate_id)
        requested_id = deterministic_batch_id(candidate.candidate_id, external_id)
        taken: set[str] = set()
        local_names: dict[str, str] = {}
        for file in candidate.files:
            name = local_file_name(file, taken)
            taken.add(name.casefold())
            local_names[file.name] = name
        record = DownloadBatch(
            batch_id=requested_id,
            candidate_id=candidate.candidate_id,
            identifier=candidate.identifier,
            filenames=[file.name for file in candidate.files],
            destination=destination,
            external_id=operation_key,
            artist=candidate.artist,
            album=candidate.album,
            license_url=candidate.license_url,
            license_label=candidate.license_label,
            queued_at=datetime.now(UTC).isoformat(),
            state="active",
            bytes_total=sum(file.size for file in candidate.files),
            file_states={file.name: "queued" for file in candidate.files},
            local_names=local_names,
            file_sizes={file.name: file.size for file in candidate.files},
        )
        if self.batches is not None:
            self.batches.save(record)
        self.start_transfer(record, candidate.files)
        return {
            "batch_id": requested_id,
            "requestedBatchId": requested_id,
            "identifier": candidate.identifier,
            "file_count": len(candidate.files),
            "artifact_path": destination,
            "destination": destination,
            "local_path": str(self.downloads_dir / PurePosixPath(destination)),
            "license_url": candidate.license_url,
            "license_label": candidate.license_label,
            "idempotent": False,
        }

    def start_transfer(self, record: DownloadBatch, files: list[ArchiveFile]) -> None:
        running = self.tasks.get(record.batch_id)
        if running is not None and not running.done():
            return
        task = asyncio.create_task(self.run_transfer(record, files))
        self.tasks[record.batch_id] = task
        task.add_done_callback(lambda finished: self.tasks.pop(record.batch_id, None))

    async def run_transfer(self, record: DownloadBatch, files: list[ArchiveFile]) -> None:
        target = self.downloads_dir / PurePosixPath(record.destination)
        target.mkdir(parents=True, exist_ok=True)
        semaphore = asyncio.Semaphore(self.config.max_parallel_downloads)
        states: dict[str, str] = dict(record.file_states)
        errors: dict[str, str] = dict(record.errors)
        retries: dict[str, int] = dict(record.retries)
        done_bytes = 0
        lock = asyncio.Lock()

        async with httpx.AsyncClient(
            headers={"User-Agent": self.config.user_agent},
            timeout=httpx.Timeout(self.config.download_timeout_seconds, connect=30),
            follow_redirects=True,
        ) as client:

            async def one(file: ArchiveFile) -> None:
                nonlocal done_bytes
                async with semaphore:
                    local = target / record.local_names.get(
                        file.name, PurePosixPath(file.name).name
                    )
                    attempt = 0
                    while True:
                        try:
                            written = await self.fetch_file(
                                client, record.identifier, file, local
                            )
                        except Exception as exc:  # noqa: BLE001 - reported, then retried
                            attempt += 1
                            retries[file.name] = attempt
                            if attempt > MAX_FILE_RETRIES:
                                async with lock:
                                    states[file.name] = "failed"
                                    errors[file.name] = f"{type(exc).__name__}: {exc}"
                                    await self.persist(
                                        record.batch_id, states, errors, retries, done_bytes
                                    )
                                return
                            await asyncio.sleep(2 * attempt)
                            continue
                        async with lock:
                            states[file.name] = "completed"
                            errors.pop(file.name, None)
                            done_bytes += written
                            await self.persist(
                                record.batch_id, states, errors, retries, done_bytes
                            )
                        return

            await asyncio.gather(*(one(file) for file in files), return_exceptions=True)

        state = (
            "completed"
            if all(value == "completed" for value in states.values())
            else "failed"
        )
        if self.batches is not None:
            self.batches.update(
                record.batch_id,
                state=state,
                file_states=states,
                errors=errors,
                retries=retries,
                bytes_done=done_bytes,
                collected=state == "completed",
            )

    async def persist(
        self,
        batch_id: str,
        states: dict[str, str],
        errors: dict[str, str],
        retries: dict[str, int],
        done_bytes: int,
    ) -> None:
        if self.batches is None:
            return
        self.batches.update(
            batch_id,
            file_states=dict(states),
            errors=dict(errors),
            retries=dict(retries),
            bytes_done=done_bytes,
        )

    async def fetch_file(
        self,
        client: httpx.AsyncClient,
        identifier: str,
        file: ArchiveFile,
        local: Path,
    ) -> int:
        """Stream one file to disk and prove it arrived intact.

        The Archive publishes an md5 for every file, so a truncated or
        mis-served transfer can be caught here instead of surfacing as a
        corrupt track after the import. Writing to a temporary name first
        keeps a half-written file from ever looking like a finished one.
        """
        url = (
            f"{self.config.base_url}/download/{quote(identifier, safe='')}/"
            f"{quote(file.name, safe='/')}"
        )
        temporary = local.with_name(local.name + ".part")
        digest = hashlib.md5()  # noqa: S324 - integrity check, not a security claim
        written = 0
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                raise ArchiveError(
                    f"archive.org download {file.name} failed ({response.status_code})"
                )
            with temporary.open("wb") as handle:
                async for chunk in response.aiter_bytes(262_144):
                    handle.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
        if file.size and written != file.size:
            with suppress(OSError):
                temporary.unlink()
            raise ArchiveError(
                f"{file.name}: {written} statt {file.size} Bytes empfangen"
            )
        if file.md5 and digest.hexdigest() != file.md5:
            with suppress(OSError):
                temporary.unlink()
            raise ArchiveError(f"{file.name}: md5 stimmt nicht mit den Metadaten überein")
        temporary.replace(local)
        return written

    # ------------------------------------------------------------------ status

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        record = self.batches.get(batch_id) if self.batches is not None else None
        if record is None:
            raise ArchiveError(
                f"Unknown download batch {batch_id}. It was queued by a different "
                "instance of this connector, or its record has expired."
            )
        target = self.downloads_dir / PurePosixPath(record.destination)
        present = (
            sorted(
                path.name
                for path in target.glob("*")
                if path.is_file() and path.suffix != ".part"
            )
            if target.is_dir()
            else []
        )
        sizes = record.file_sizes
        result: dict[str, Any] = {
            "batch_id": batch_id,
            "identifier": record.identifier,
            "state": record.state,
            "file_count": len(record.filenames),
            "files_seen": sum(
                1 for value in record.file_states.values() if value == "completed"
            ),
            "bytes_done": record.bytes_done,
            "bytes_total": record.bytes_total,
            "destination": record.destination,
            "artifact_path": record.destination,
            "local_path": str(target),
            "license_url": record.license_url,
            "license_label": record.license_label,
            # ``size`` and ``bytesTransferred`` are spelled the way the
            # orchestrator's progress reader expects, so the dashboard shows a
            # bar for this source without a second code path. Progress is
            # tracked per file, not per byte, so a running file reports zero
            # until it is verified — an unverified file is not progress.
            "files": [
                {
                    "filename": name,
                    "local_name": record.local_names.get(name, ""),
                    "state": record.file_states.get(name, "unknown"),
                    "size": sizes.get(name, 0),
                    "bytesTransferred": (
                        sizes.get(name, 0)
                        if record.file_states.get(name) == "completed"
                        else 0
                    ),
                    "error": record.errors.get(name, ""),
                    "retries": record.retries.get(name, 0),
                }
                for name in record.filenames
            ],
            "errors": record.errors,
        }
        if record.state == "completed":
            result["collected"] = {
                "moved": len(present),
                "missing": [],
                "path": str(target),
                "already_collected": record.collected,
            }
        return result

    async def wait_for_batch(
        self,
        batch_id: str,
        *,
        timeout_seconds: int = 3600,
        poll_seconds: int = 5,
    ) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        last: Any = None
        while asyncio.get_running_loop().time() < deadline:
            last = self.get_batch(batch_id)
            state = str(last.get("state") or "unknown")
            if state in {"completed", "failed"}:
                return {"state": state, "batch": last}
            await asyncio.sleep(max(2, poll_seconds))
        return {"state": "timeout", "batch": last}

    def list_downloads(self) -> list[dict[str, Any]]:
        if self.batches is None:
            return []
        return [
            {
                "batch_id": batch.batch_id,
                "identifier": batch.identifier,
                "artist": batch.artist,
                "album": batch.album,
                "state": batch.state,
                "destination": batch.destination,
                "queued_at": batch.queued_at,
            }
            for batch in self.batches.all()
        ]


__all__ = [
    "LOSSLESS_EXTENSIONS",
    "ArchiveClient",
    "ArchiveError",
    "deterministic_batch_id",
    "local_file_name",
    "sanitize_destination",
]
