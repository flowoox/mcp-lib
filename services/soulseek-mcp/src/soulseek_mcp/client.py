from __future__ import annotations

import asyncio
import uuid
from contextlib import suppress
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import safe_relative_destination, safe_segment, stable_id

from .config import RuntimeConfig
from .matcher import build_album_candidates, extract_search_responses
from .models import AlbumCandidate

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


def classify_batch(payload: Any) -> str:
    states: list[str] = []
    for item in walk_dicts(payload):
        raw = get_case_insensitive(item, "state", "status")
        if raw is not None:
            states.append(str(raw).casefold().replace(" ", ""))
    if not states:
        return "unknown"
    if any(state in FAILED_STATES for state in states):
        return "failed"
    if all(state in COMPLETE_STATES for state in states):
        return "completed"
    if any(state in ACTIVE_STATES for state in states):
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
    def __init__(self, config: RuntimeConfig, *, timeout: float = 45):
        self.config = config
        self.timeout = timeout

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
        requested_id = deterministic_batch_id(candidate_id, external_id)
        batch_path = (
            "/api/v0/transfers/downloads/batches/"
            f"{quote(requested_id, safe='')}"
        )
        existing = await self.request(
            "GET",
            batch_path,
            allow_not_found=True,
        )
        if existing is None:
            return None
        output = existing if isinstance(existing, dict) else {"result": existing}
        output.setdefault("batch_id", requested_id)
        output.setdefault("requestedBatchId", requested_id)
        if destination:
            normalized_destination = sanitize_destination(destination)
            output.setdefault("artifact_path", normalized_destination)
            output.setdefault("destination", normalized_destination)
        output["idempotent"] = True
        return output

    async def queue_candidate(
        self,
        candidate: AlbumCandidate,
        *,
        destination: str | None = None,
        external_id: str | None = None,
    ) -> dict[str, Any]:
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

        payload = {
            "id": requested_id,
            "searchId": candidate.search_id,
            "username": candidate.username,
            "files": [
                {"filename": file.filename, "size": file.size}
                for file in candidate.files
            ],
            "options": {
                "destination": destination,
                "externalId": operation_key,
            },
        }
        result = await self.request(
            "POST", "/api/v0/transfers/downloads/batches", json=payload
        )
        output = result if isinstance(result, dict) else {"result": result}
        output.setdefault("batch_id", requested_id)
        output.setdefault("requestedBatchId", requested_id)
        output.setdefault("artifact_path", destination)
        output.setdefault("destination", destination)
        output.setdefault("idempotent", False)
        return output

    async def list_downloads(self) -> Any:
        return await self.request("GET", "/api/v0/transfers/downloads")

    async def get_batch(self, batch_id: str) -> Any:
        return await self.request(
            "GET",
            f"/api/v0/transfers/downloads/batches/{quote(batch_id, safe='')}",
        )

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
            state = classify_batch(last)
            if state in {"completed", "failed"}:
                return {"state": state, "batch": last}
            await asyncio.sleep(max(2, poll_seconds))
        return {"state": "timeout", "batch": last}
