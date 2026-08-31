from __future__ import annotations

import asyncio
import math
import shutil
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import (
    resolve_contained_path,
    safe_relative_destination,
    safe_segment,
    stable_id,
)

from .config import RuntimeConfig
from .matcher import build_album_candidates, extract_search_responses
from .models import AlbumCandidate, DownloadBatch
from .repository import BatchRepository

COMPLETE_STATES = {"completed", "complete", "succeeded", "success", "finished"}
FAILED_STATES = {
    "aborted",
    "cancelled",
    "canceled",
    "denied",
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
AUDIO_EXTENSIONS = {
    ".aac",
    ".aif",
    ".aiff",
    ".flac",
    ".m4a",
    ".mp3",
    ".ogg",
    ".opus",
    ".wav",
}
# How often one dropped file is asked for again before the album counts as
# lost. Peers abort single transfers often enough that one attempt is not a
# verdict, and often enough that endless retries would hide a dead peer.
MAX_FILE_RETRIES = 2


class SlskdError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ReconnectCoordinator:
    """Serialize reconnects and suppress reconnect storms in one MCP process."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.last_attempt_at: float | None = None


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


def is_audio_filename(value: str) -> bool:
    return remote_to_posix(value).suffix.casefold() in AUDIO_EXTENSIONS


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
        reconnect: ReconnectCoordinator | None = None,
    ):
        self.config = config
        self.timeout = timeout
        # An album is a local idea; slskd only knows users and files.
        self.batches = batches
        self.downloads_dir = downloads_dir
        self.reconnect = reconnect or ReconnectCoordinator()

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        return headers

    def archive_download_folder(self, folder: str, namespace: str) -> dict[str, Any]:
        """Move one rejected artifact aside through a constrained operation."""
        root = self.downloads_dir.resolve()
        source = resolve_contained_path(root, folder)
        if source == root or ".radar-retry-archive" in source.relative_to(root).parts:
            raise ValueError("Only an active album folder can be archived")
        if not source.is_dir() or not any(source.iterdir()):
            return {"archived": False, "archived_path": ""}
        archive_root = root / ".radar-retry-archive" / safe_segment(namespace)
        archive_root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        target = archive_root / f"{safe_segment(source.name)}-{stamp}"
        source.rename(target)
        return {"archived": True, "archived_path": str(target)}

    def cleanup_download_folder(self, folder: str) -> dict[str, Any]:
        """Remove one verified Radar artifact, never an arbitrary download path.

        The caller still has to prove that Traxx contains the complete album.
        This filesystem boundary independently limits deletion to descendants
        of ``/downloads/library`` so a bad or forged MCP argument cannot erase
        the share, retry archive, quarantine, or the downloads root itself.
        """
        root = self.downloads_dir.resolve()
        source = resolve_contained_path(root, folder)
        relative = source.relative_to(root)
        # Radar writes library/<profile>/<artist>/<album>. Requiring all four
        # components prevents a forged call from deleting a whole profile or
        # artist tree while still allowing a nested album/disc directory.
        if not relative.parts or relative.parts[0] != "library" or len(relative.parts) < 4:
            raise ValueError("Only a Radar album folder below library can be cleaned")
        if not source.exists():
            return {"removed": False, "path": str(source), "reason": "missing"}
        if not source.is_dir():
            raise ValueError("Only a Radar album directory can be cleaned")
        shutil.rmtree(source)
        return {"removed": True, "path": str(source)}

    def cleanup_retry_archive(
        self, *, retention_hours: int = 72, limit: int = 100
    ) -> dict[str, Any]:
        """Remove bounded, expired retry attempts from the private archive.

        The caller cannot provide a path. Only individual attempt directories
        below ``.radar-retry-archive/<recommendation>/`` are considered, and a
        directory is retained while any file in it is newer than the cutoff.
        Active library, repair and incomplete directories are outside this
        boundary and therefore cannot be removed by this operation.
        """
        retention_hours = max(1, int(retention_hours))
        limit = max(1, min(int(limit), 1000))
        archive_root = self.downloads_dir.resolve() / ".radar-retry-archive"
        if not archive_root.is_dir() or archive_root.is_symlink():
            return {
                "removed": [],
                "freed_bytes": 0,
                "retained_recent": 0,
                "errors": {},
                "retention_hours": retention_hours,
            }

        cutoff = datetime.now(UTC).timestamp() - retention_hours * 3600
        candidates: list[tuple[float, int, Path, Path]] = []
        retained_recent = 0
        errors: dict[str, str] = {}
        for namespace in sorted(archive_root.iterdir(), key=lambda item: item.name):
            if not namespace.is_dir() or namespace.is_symlink():
                continue
            for attempt in sorted(namespace.iterdir(), key=lambda item: item.name):
                if not attempt.is_dir() or attempt.is_symlink():
                    continue
                newest = attempt.stat().st_mtime
                size = 0
                try:
                    for item in attempt.rglob("*"):
                        stat = item.lstat()
                        newest = max(newest, stat.st_mtime)
                        if item.is_file() and not item.is_symlink():
                            size += stat.st_size
                except OSError as exc:
                    errors[attempt.relative_to(archive_root).as_posix()] = str(exc)
                    continue
                if newest > cutoff:
                    retained_recent += 1
                    continue
                candidates.append((newest, size, namespace, attempt))

        removed: list[str] = []
        freed_bytes = 0
        for _newest, size, namespace, attempt in sorted(candidates)[:limit]:
            relative = attempt.relative_to(archive_root).as_posix()
            try:
                shutil.rmtree(attempt)
                removed.append(relative)
                freed_bytes += size
                with suppress(OSError):
                    namespace.rmdir()
            except OSError as exc:
                errors[relative] = str(exc)
        return {
            "removed": removed,
            "freed_bytes": freed_bytes,
            "retained_recent": retained_recent,
            "errors": errors,
            "retention_hours": retention_hours,
        }

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
                f"{response.text[:1200]}",
                status_code=response.status_code,
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

        status = await self.ensure_connected()
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
            "auto_reconnect_triggered": status["reconnect_triggered"],
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

        # This method is also used by the automatic path. Keep even internal
        # callers bounded if a future configuration or refactor supplies a
        # surprising value.
        wait_seconds = max(0, min(int(wait_seconds), 60))
        await self.request("PUT", "/api/v0/server", json={"action": "connect"})
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        status = already
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(1.5, remaining))
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

    @staticmethod
    def _disconnected_error(
        status: dict[str, Any],
        *,
        detail: str = "",
    ) -> SlskdError:
        state = str(status.get("state") or "unbekannt")[:120]
        suffix = f" {detail}" if detail else ""
        return SlskdError(
            "slskd ist erreichbar, aber nicht im Soulseek-Netz angemeldet "
            f"(Zustand: {state}). Ohne Anmeldung schlägt jede Suche mit 409 fehl."
            f"{suffix}"
        )

    async def ensure_connected(self) -> dict[str, Any]:
        """Return a logged-in state, attempting one bounded reconnect if needed.

        Every client created by the MCP server shares one coordinator. This
        prevents concurrent searches from sending a burst of connect requests,
        while the cooldown prevents repeated failed credentials from creating
        an endless reconnect loop.
        """
        status = await self.server_status()
        if status["logged_in"]:
            return {**status, "reconnect_triggered": False}
        if not self.config.auto_reconnect:
            raise self._disconnected_error(
                status,
                detail="Automatische Wiederverbindung ist deaktiviert.",
            )

        async with self.reconnect.lock:
            # A concurrent request may have completed the login while this one
            # waited for the lock.
            status = await self.server_status()
            if status["logged_in"]:
                return {**status, "reconnect_triggered": False}

            loop = asyncio.get_running_loop()
            now = loop.time()
            if self.reconnect.last_attempt_at is not None:
                elapsed = now - self.reconnect.last_attempt_at
                if elapsed < self.config.reconnect_cooldown_seconds:
                    retry_after = math.ceil(
                        self.config.reconnect_cooldown_seconds - elapsed
                    )
                    raise self._disconnected_error(
                        status,
                        detail=(
                            "Ein automatischer Wiederverbindungsversuch lief bereits; "
                            f"der nächste ist frühestens in {retry_after} Sekunden erlaubt."
                        ),
                    )

            # Set the timestamp before performing I/O so even a rejected or
            # failed PUT is subject to the same bounded cooldown.
            self.reconnect.last_attempt_at = now
            try:
                connected = await self.connect_soulseek(
                    wait_seconds=self.config.reconnect_wait_seconds
                )
            finally:
                # Start the full cooldown after the I/O completes as well. A
                # slow failed login must not consume most of its own cooldown.
                self.reconnect.last_attempt_at = loop.time()
            if not connected["logged_in"]:
                raise self._disconnected_error(
                    connected,
                    detail=(
                        "Der automatische Wiederverbindungsversuch wurde ausgelöst, "
                        "aber nicht rechtzeitig abgeschlossen. Prüfe das Konto in slskd."
                    ),
                )
            return {**connected, "reconnect_triggered": bool(connected["triggered"])}

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
        connection = await self.ensure_connected()
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
        try:
            started = await self.request("POST", "/api/v0/searches", json=payload)
        except SlskdError as exc:
            # A disconnect can race the preflight. Retry exactly once, and only
            # when slskd itself confirms that the 409 came with a logged-out
            # state. Other conflicts must keep their original meaning.
            if exc.status_code != 409 or connection["reconnect_triggered"]:
                raise
            status = await self.server_status()
            if status["logged_in"]:
                raise
            connection = await self.ensure_connected()
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
            "auto_reconnect_triggered": connection["reconnect_triggered"],
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
        # A cancelled operation is historical evidence, not an active queue
        # entry. Returning it as idempotent made every Radar retry a no-op.
        # Saving a new DownloadBatch below reuses the deterministic key while
        # resetting cancelled/retries/queued_at to the new attempt.
        if stored.cancelled:
            return None
        target = self.downloads_dir / PurePosixPath(stored.destination)
        if stored.collected and not target.is_dir():
            # The verified retention job may have removed the local artifact.
            # A later repair must be able to acquire it again.
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
        usage = shutil.disk_usage(self.downloads_dir)
        requested_bytes = sum(max(0, int(file.size or 0)) for file in candidate.files)
        reserved_bytes = max(
            self.config.minimum_free_space_gib * 1024**3,
            math.ceil(usage.total * self.config.minimum_free_space_percent / 100),
        )
        if usage.free - requested_bytes < reserved_bytes:
            raise SlskdError(
                "Download wegen Speicherreserve blockiert: "
                f"{usage.free / 1024**3:.1f} GiB frei, "
                f"{requested_bytes / 1024**3:.1f} GiB angefordert, "
                f"{reserved_bytes / 1024**3:.1f} GiB Reserve erforderlich"
            )
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
        if record.cancelled:
            return {
                "batch_id": batch_id,
                "retried": [],
                "username": record.username,
                "state": "cancelled",
                "file_count": len(record.filenames),
                "files_seen": 0,
                "destination": record.destination,
                "artifact_path": record.destination,
                "local_path": str(
                    self.downloads_dir / PurePosixPath(record.destination)
                ),
                "files": [],
            }
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
        audio_wanted = {
            normalize_remote_path(name)
            for name in record.filenames
            if is_audio_filename(name)
        }
        audio_files = [
            item
            for item in files
            if normalize_remote_path(
                str(get_case_insensitive(item, "filename", "fileName") or "")
            )
            in audio_wanted
        ]
        required_files = audio_files if audio_wanted else files
        required_count = len(audio_wanted) if audio_wanted else len(record.filenames)
        state = classify_batch({"files": required_files}) if required_files else "unknown"
        retried: list[str] = []
        if state == "failed":
            state, retried = await self.retry_failed_files(record, required_files)
        result: dict[str, Any] = {
            "batch_id": batch_id,
            "retried": retried,
            "username": record.username,
            "state": state,
            "file_count": len(record.filenames),
            "files_seen": len(files),
            "audio_file_count": len(audio_wanted),
            "audio_files_seen": len(audio_files),
            "destination": record.destination,
            "artifact_path": record.destination,
            "local_path": str(self.downloads_dir / PurePosixPath(record.destination)),
            "files": files,
        }
        if state == "completed" and len(required_files) >= required_count:
            completed_files = [
                item
                for item in files
                if classify_transfer_state(
                    str(get_case_insensitive(item, "state", "status") or "")
                )
                == "completed"
            ]
            result["collected"] = self.collect_batch(record, completed_files)
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
