from __future__ import annotations

import asyncio
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
from .matcher import build_album_candidates, extract_search_responses
from .models import AlbumCandidate, DownloadBatch
from .repository import BatchRepository

COMPLETE_STATES = {"completed", "complete", "succeeded", "success", "finished"}
FAILED_STATES = {
    "cancelled",
    "canceled",
    "errored",
    "error",
    "failed",
    "rejected",
    "timedout",
    "timed_out",
}
ACTIVE_STATES = {
    "queued",
    "requested",
    "initializing",
    "inprogress",
    "in_progress",
    "downloading",
    "transferring",
}
# How often one dropped file is asked for again before the album counts as
# lost. Peers abort single transfers often enough that one attempt is not a
# verdict, and often enough that endless retries would hide a dead peer.
MAX_FILE_RETRIES = 2


class SlskdError(RuntimeError):
    pass


def deterministic_batch_id(candidate_id: str, external_id: str | None = None) -> str:
    operation_key = external_id or stable_id("album", candidate_id)
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"flowoox:soulseek:{operation_key}:{candidate_id}",
        )
    )


def walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def remote_to_posix(value: str) -> PurePosixPath:
    """The remote path with its own spelling kept.

    Peers send Windows separators; only those are translated. The case has to
    survive, because the file slskd wrote to disk carries it and Linux will
    not find "deep.flac" when the file is called "Deep.flac".
    """
    return PurePosixPath((value or "").replace("\\", "/").strip())


def normalize_remote_path(value: str) -> str:
    """One spelling for comparing two remote paths, and only for that."""
    return str(remote_to_posix(value)).casefold()


def classify_transfer_state(raw: str) -> str:
    """One word for one transfer, out of what slskd actually writes.

    slskd reports a compound state: "Completed, Succeeded" but also
    "Completed, Errored" and "Completed, Cancelled". Reading only the first
    word would count every abandoned transfer as a success, and reading the
    whole string matches nothing at all.
    """
    words = [
        word for word in str(raw or "").casefold().replace(" ", "").split(",") if word
    ]
    if not words:
        return "unknown"
    if any(word in FAILED_STATES for word in words):
        return "failed"
    if any(word in ACTIVE_STATES for word in words):
        return "active"
    if all(word in COMPLETE_STATES for word in words):
        return "completed"
    return words[0]


def classify_batch(payload: Any) -> str:
    states: list[str] = []
    for item in walk_dicts(payload):
        raw = get_case_insensitive(item, "state", "status")
        if raw is not None:
            states.append(classify_transfer_state(str(raw)))
    if not states:
        return "unknown"
    if any(state == "failed" for state in states):
        return "failed"
    if all(state == "completed" for state in states):
        return "completed"
    if any(state == "active" for state in states):
        return "active"
    return states[0]


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


class SlskdClient:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        timeout: float = 45,
        batches: BatchRepository | None = None,
        downloads_dir: Path = Path("/downloads"),
    ):
        self.config = config
        self.timeout = timeout
        # An album is a local idea; slskd only knows users and files.
        self.batches = batches
        self.downloads_dir = downloads_dir

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            timeout=self.timeout,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
        if response.status_code == 404 and allow_not_found:
            return None
        if response.status_code >= 400:
            raise SlskdError(
                f"slskd {method} {path} failed ({response.status_code}): "
                f"{response.text[:1200]}"
            )
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return {"text": response.text}

    async def health(self) -> dict[str, Any]:
        """Report reachability *and* whether slskd is logged into Soulseek.

        Answering only "the API responds" was misleading: searching fails with
        409 while slskd is disconnected, so a green connector test could be
        followed by every search failing.
        """
        await self.request("GET", "/api/v0/searches")

        status = await self.server_status()
        if not status["logged_in"]:
            raise SlskdError(
                f"slskd ist erreichbar, aber nicht im Soulseek-Netz angemeldet "
                f"(Zustand: {status['state'] or 'unbekannt'}). Ohne Anmeldung schlägt "
                "jede Suche mit 409 fehl. Rufe connect_soulseek auf, oder prüfe "
                "Benutzername und Passwort, falls die Anmeldung abgelehnt wird."
            )
        shared = await self.shared_file_count()
        warnings: list[str] = []
        if shared == 0:
            # Not an error: searching works. But peers answer searches from
            # users who share something, so an empty share reliably produces
            # zero results and looks like a broken connector.
            warnings.append(
                "Es sind keine Dateien freigegeben. Im Soulseek-Netz antworten die "
                "meisten Gegenstellen nur Nutzern, die selbst etwas teilen — ohne "
                "Freigabe bleiben Suchen typischerweise ohne Treffer. Lege Musik in "
                "das Freigabeverzeichnis (im Compose auf /music gemountet)."
            )
        return {
            "ok": True,
            "base_url": self.config.base_url,
            "soulseek_state": status["state"],
            "soulseek_username": status["username"],
            "logged_in": True,
            "shared_files": shared,
            "warnings": warnings,
            "lossless_only": self.config.lossless_only,
            "minimum_lossy_bitrate_kbps": self.config.minimum_lossy_bitrate_kbps,
        }

    async def shared_file_count(self) -> int:
        """Total files slskd offers to the network, across all share hosts."""
        payload: Any = None
        with suppress(Exception):
            payload = await self.request("GET", "/api/v0/shares", allow_not_found=True)
        total = 0
        for entry in payload if isinstance(payload, list) else []:
            if isinstance(entry, dict):
                with suppress(TypeError, ValueError):
                    total += int(get_case_insensitive(entry, "files", default=0) or 0)
        if isinstance(payload, dict):
            for group in payload.values():
                for entry in group if isinstance(group, list) else []:
                    if isinstance(entry, dict):
                        with suppress(TypeError, ValueError):
                            total += int(get_case_insensitive(entry, "files", default=0) or 0)
        return total

    async def server_status(self) -> dict[str, Any]:
        """Read the Soulseek connection state.

        The explicit booleans are authoritative; the state string is only for
        display and reads "None" before the first attempt.
        """
        detail: Any = None
        with suppress(Exception):
            detail = await self.request("GET", "/api/v0/server", allow_not_found=True)
        if not isinstance(detail, dict):
            return {"state": "", "username": "", "logged_in": False, "connected": False}
        return {
            "state": str(get_case_insensitive(detail, "state", default="") or ""),
            "username": str(get_case_insensitive(detail, "username", default="") or ""),
            "logged_in": bool(get_case_insensitive(detail, "isLoggedIn", default=False)),
            "connected": bool(get_case_insensitive(detail, "isConnected", default=False)),
        }

    async def connect_soulseek(self, *, wait_seconds: int = 25) -> dict[str, Any]:
        """Ask slskd to log into the Soulseek network and wait for the result.

        slskd reads the account from its configuration file at startup. Writing
        credentials afterwards leaves it sitting in state "None" without ever
        attempting a login, which is why configuring an account has to be
        followed by this.
        """
        already = await self.server_status()
        if already["logged_in"]:
            return {**already, "triggered": False}

        await self.request("PUT", "/api/v0/server", json={"action": "connect"})
        deadline = asyncio.get_running_loop().time() + wait_seconds
        status = already
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(1.5)
            status = await self.server_status()
            if status["logged_in"]:
                return {**status, "triggered": True}
        return {
            **status,
            "triggered": True,
            "note": (
                "Die Anmeldung wurde angestossen, war aber innerhalb der Wartezeit "
                "nicht abgeschlossen. Ist der Benutzername schon vergeben, lehnt der "
                "Soulseek-Server ihn ab — dann hilft ein anderer Name."
            ),
        }

    async def search_album(
        self,
        *,
        artist: str,
        album: str,
        expected_track_count: int | None = None,
        timeout_seconds: int | None = None,
        max_candidates: int = 20,
        lossless_only: bool | None = None,
        minimum_lossy_bitrate_kbps: int | None = None,
        search_text: str | None = None,
    ) -> tuple[str, list[AlbumCandidate], dict[str, Any]]:
        timeout_seconds = timeout_seconds or self.config.search_timeout
        payload = {
            # Peers match every term against the file path, so the query is an
            # AND over words. A caller that got no answer at all may hand in a
            # shorter one; ranking still happens against artist and album.
            "searchText": search_text or f"{artist} {album}",
            "fileLimit": 10000,
            "filterResponses": True,
            "maximumPeerQueueLength": 1000000,
            "minimumPeerUploadSpeed": 0,
            # A known track count is the truth about this release: taking the
            # maximum would demand four files from a single and drop every
            # answer before it could be ranked.
            "minimumResponseFileCount": (
                expected_track_count
                if expected_track_count
                else self.config.minimum_tracks
            ),
            "responseLimit": self.config.result_limit,
            # slskd takes this in milliseconds. Handing it the seconds value
            # ended every search after 20 ms — long before a peer could
            # answer, which is why the network looked empty. Measured on the
            # same query: 20 gives 0 responses, 20000 gives 10.
            "searchTimeout": timeout_seconds * 1000,
        }
        started = await self.request("POST", "/api/v0/searches", json=payload)
        if not isinstance(started, dict):
            raise SlskdError("slskd returned an unexpected search response")
        search_id = str(
            get_case_insensitive(started, "id", "searchId", default="") or ""
        )
        if not search_id:
            raise SlskdError("slskd did not return a search id")
        result = started
        deadline = asyncio.get_running_loop().time() + timeout_seconds + 8
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(1)
            result = await self.request(
                "GET",
                f"/api/v0/searches/{quote(search_id, safe='')}",
                params={"includeResponses": "true"},
            )
            if isinstance(result, dict):
                complete = get_case_insensitive(result, "isComplete", "completed")
                state = str(
                    get_case_insensitive(result, "state", "status", default="")
                ).casefold()
                if complete is True or state in {
                    "completed",
                    "complete",
                    "stopped",
                    "timedout",
                    "timed_out",
                }:
                    break
        # Per-search overrides: the stored quality gate is the default, but a
        # caller that already knows nothing lossless exists may lower it once
        # rather than change the configuration for everything.
        effective_lossless = (
            self.config.lossless_only if lossless_only is None else lossless_only
        )
        effective_bitrate = (
            self.config.minimum_lossy_bitrate_kbps
            if minimum_lossy_bitrate_kbps is None
            else minimum_lossy_bitrate_kbps
        )
        candidates, rejected = build_album_candidates(
            payload=result,
            artist=artist,
            album=album,
            search_id=search_id,
            preferred_formats=self.config.preferred_formats,
            minimum_tracks=self.config.minimum_tracks,
            expected_track_count=expected_track_count,
            lossless_only=effective_lossless,
            minimum_lossy_bitrate_kbps=effective_bitrate,
        )
        stats = {
            "responses": len(extract_search_responses(result)),
            "rejected": rejected,
            "lossless_only": effective_lossless,
            "minimum_lossy_bitrate_kbps": effective_bitrate,
            "search_text": payload["searchText"],
        }
        return (search_id, candidates[:max_candidates], stats)

    async def get_existing_operation_batch(
        self,
        *,
        candidate_id: str,
        external_id: str | None = None,
        destination: str | None = None,
    ) -> dict[str, Any] | None:
        """Return an already queued batch, or None.

        The record is ours: slskd knows users and files, not albums, so
        "have I queued this before" can only be answered from the local batch
        store.
        """
        requested_id = deterministic_batch_id(candidate_id, external_id)
        if self.batches is None:
            return None
        stored = self.batches.get(requested_id)
        if stored is None:
            return None
        output = await self.get_batch(requested_id)
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
        """Queue every file of one album folder with the peer that holds it.

        slskd offers no batch route — ``POST /transfers/downloads/batches`` is
        read as a *user* named "batches" and answers "User batches appears to
        be offline". The real route takes a plain list of files per user, so
        the album is queued that way and held together by a local record.
        """
        destination = (
            sanitize_destination(destination)
            if destination
            else safe_relative_destination(candidate.artist, candidate.album)
        )
        operation_key = external_id or stable_id("album", candidate.candidate_id)
        requested_id = deterministic_batch_id(candidate.candidate_id, external_id)
        existing = await self.get_existing_operation_batch(
            candidate_id=candidate.candidate_id,
            external_id=external_id,
            destination=destination,
        )
        if existing is not None:
            return existing

        payload = [
            {"filename": file.filename, "size": file.size}
            for file in candidate.files
        ]
        if not payload:
            raise SlskdError(f"Candidate {candidate.candidate_id} has no files to queue")
        await self.request(
            "POST",
            f"/api/v0/transfers/downloads/{quote(candidate.username, safe='')}",
            json=payload,
        )
        record = DownloadBatch(
            batch_id=requested_id,
            candidate_id=candidate.candidate_id,
            username=candidate.username,
            filenames=[file.filename for file in candidate.files],
            destination=destination,
            external_id=operation_key,
            artist=candidate.artist,
            album=candidate.album,
            queued_at=datetime.now(UTC).isoformat(),
        )
        if self.batches is not None:
            self.batches.save(record)
        return {
            "batch_id": requested_id,
            "requestedBatchId": requested_id,
            "username": candidate.username,
            "file_count": len(payload),
            "artifact_path": destination,
            "destination": destination,
            "local_path": str(self.downloads_dir / PurePosixPath(destination)),
            "idempotent": False,
        }

    async def cancel_batch(self, batch_id: str, *, remove: bool = False) -> dict[str, Any]:
        """Stop an album's transfers, and optionally forget them.

        slskd cancels per file, so an album is cancelled by cancelling each of
        its files. Files that already finished are left alone: cancelling them
        would delete a download that succeeded.
        """
        record = self.batches.get(batch_id) if self.batches is not None else None
        if record is None:
            raise SlskdError(f"Unknown download batch {batch_id}")
        payload = await self.request(
            "GET",
            f"/api/v0/transfers/downloads/{quote(record.username, safe='')}",
            allow_not_found=True,
        )
        wanted = {normalize_remote_path(name) for name in record.filenames}
        cancelled: list[str] = []
        failed: dict[str, str] = {}
        for item in walk_dicts(payload):
            filename = str(get_case_insensitive(item, "filename", "fileName") or "")
            if not filename or normalize_remote_path(filename) not in wanted:
                continue
            state = classify_transfer_state(
                str(get_case_insensitive(item, "state", "status") or "")
            )
            if state == "completed" and not remove:
                continue
            transfer_id = str(get_case_insensitive(item, "id", default="") or "")
            if not transfer_id:
                continue
            path = (
                f"/api/v0/transfers/downloads/{quote(record.username, safe='')}/"
                f"{quote(transfer_id, safe='')}"
            )
            try:
                await self.request(
                    "DELETE",
                    path,
                    params={"remove": "true"} if remove else None,
                    allow_not_found=True,
                )
                cancelled.append(remote_to_posix(filename).name)
            except SlskdError as exc:
                failed[remote_to_posix(filename).name] = str(exc)[:200]
        if self.batches is not None:
            self.batches.update(batch_id, cancelled=True)
        return {
            "batch_id": batch_id,
            "cancelled": cancelled,
            "failed": failed,
            "removed": remove,
        }

    async def list_downloads(self) -> Any:
        return await self.request("GET", "/api/v0/transfers/downloads")

    async def get_batch(self, batch_id: str) -> dict[str, Any]:
        """Report one album's transfers, and collect them once they are done.

        The state has to be assembled from the peer's transfer list because
        slskd tracks files, not albums. When every file has arrived they are
        moved into the folder the caller asked for — slskd drops them under the
        remote folder name, which is not where the import looks.
        """
        record = self.batches.get(batch_id) if self.batches is not None else None
        if record is None:
            raise SlskdError(
                f"Unknown download batch {batch_id}. It was queued by a different "
                "instance of this connector, or its record has expired."
            )
        payload = await self.request(
            "GET",
            f"/api/v0/transfers/downloads/{quote(record.username, safe='')}",
            allow_not_found=True,
        )
        wanted = {normalize_remote_path(name) for name in record.filenames}
        files: list[dict[str, Any]] = []
        for item in walk_dicts(payload):
            filename = get_case_insensitive(item, "filename", "fileName")
            if not filename or normalize_remote_path(str(filename)) not in wanted:
                continue
            if get_case_insensitive(item, "state", "status") is None:
                continue
            files.append(item)
        state = classify_batch({"files": files}) if files else "unknown"
        retried: list[str] = []
        if state == "failed":
            state, retried = await self.retry_failed_files(record, files)
        result: dict[str, Any] = {
            "batch_id": batch_id,
            "retried": retried,
            "username": record.username,
            "state": state,
            "file_count": len(record.filenames),
            "files_seen": len(files),
            "destination": record.destination,
            "artifact_path": record.destination,
            "local_path": str(self.downloads_dir / PurePosixPath(record.destination)),
            "files": files,
        }
        if state == "completed" and len(files) >= len(record.filenames):
            result["collected"] = self.collect_batch(record, files)
        return result

    async def retry_failed_files(
        self, record: DownloadBatch, files: list[dict[str, Any]]
    ) -> tuple[str, list[str]]:
        """Ask again for the files a peer dropped, before giving the album up.

        Peers abort single transfers routinely — measured on five albums, four
        of them arrived complete except for one or two files that ended as
        "Completed, Errored". Declaring the whole album lost over that throws
        away a download that is already ninety percent done.
        """
        failed = [
            str(get_case_insensitive(item, "filename", "fileName") or "")
            for item in files
            if classify_transfer_state(
                str(get_case_insensitive(item, "state", "status") or "")
            )
            == "failed"
        ]
        sizes = {
            normalize_remote_path(
                str(get_case_insensitive(item, "filename", "fileName") or "")
            ): int(get_case_insensitive(item, "size", "fileSize", default=0) or 0)
            for item in files
        }
        retries = dict(record.retries)
        again = [
            name
            for name in failed
            if name and retries.get(normalize_remote_path(name), 0) < MAX_FILE_RETRIES
        ]
        if not again:
            return "failed", []
        payload = [
            {"filename": name, "size": sizes.get(normalize_remote_path(name), 0)}
            for name in again
        ]
        try:
            await self.request(
                "POST",
                f"/api/v0/transfers/downloads/{quote(record.username, safe='')}",
                json=payload,
            )
        except SlskdError:
            # The peer may be gone for good; the next poll decides.
            return "failed", []
        for name in again:
            key = normalize_remote_path(name)
            retries[key] = retries.get(key, 0) + 1
        if self.batches is not None:
            self.batches.update(record.batch_id, retries=retries)
        return "active", [PurePosixPath(remote_to_posix(name)).name for name in again]

    def collect_batch(
        self, record: DownloadBatch, files: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Move a finished album into the folder that was requested for it.

        slskd writes each file under the remote folder's own name, so a
        download ends up somewhere the importer would never look. Moving is
        done once and then remembered, because a second pass would find the
        sources gone and report a failure that did not happen.
        """
        target = self.downloads_dir / PurePosixPath(record.destination)
        if record.collected and target.is_dir():
            return {"moved": 0, "already_collected": True, "path": str(target)}
        target.mkdir(parents=True, exist_ok=True)
        moved = 0
        missing: list[str] = []
        for item in files:
            remote = str(get_case_insensitive(item, "filename", "fileName") or "")
            source = self.locate_downloaded_file(remote, target)
            if source is None:
                missing.append(remote_to_posix(remote).name)
                continue
            destination_file = target / source.name
            if source == destination_file:
                continue
            with suppress(OSError):
                destination_file.parent.mkdir(parents=True, exist_ok=True)
                source.replace(destination_file)
                moved += 1
                # An emptied download folder is noise for the next scan.
                with suppress(OSError):
                    source.parent.rmdir()
        if self.batches is not None and not missing:
            self.batches.update(record.batch_id, collected=True)
        return {
            "moved": moved,
            "missing": missing,
            "path": str(target),
            "already_collected": False,
        }

    def locate_downloaded_file(self, remote: str, target: Path) -> Path | None:
        """Find where slskd put one downloaded file.

        The usual place is ``<downloads>/<remote folder name>/<file>``. The
        search by name is the fallback for the cases where slskd sanitized the
        folder differently than expected.
        """
        posix = remote_to_posix(remote)
        guess = self.downloads_dir / posix.parent.name / posix.name
        if guess.is_file():
            return guess
        direct = self.downloads_dir / posix.name
        if direct.is_file():
            return direct
        for found in self.downloads_dir.rglob(posix.name):
            if found.is_file() and target not in found.parents:
                return found
        settled = target / posix.name
        return settled if settled.is_file() else None

    async def browse_user(self, username: str) -> Any:
        return await self.request(
            "GET", f"/api/v0/users/{quote(username, safe='')}/browse"
        )

    async def wait_for_batch(
        self,
        batch_id: str,
        *,
        timeout_seconds: int = 3600,
        poll_seconds: int = 10,
    ) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        last: Any = None
        while asyncio.get_running_loop().time() < deadline:
            last = await self.get_batch(batch_id)
            state = str(last.get("state") or "unknown")
            if state in {"completed", "failed"}:
                return {"state": state, "batch": last}
            await asyncio.sleep(max(2, poll_seconds))
        return {"state": "timeout", "batch": last}
