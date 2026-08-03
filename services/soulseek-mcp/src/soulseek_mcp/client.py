from __future__ import annotations

import asyncio
import uuid
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import safe_relative_destination, safe_segment, stable_id

from .config import RuntimeConfig
from .matcher import build_album_candidates
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
    ) -> Any:
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            timeout=self.timeout,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
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
        data = await self.request("GET", "/api/v0/searches")
        return {
            "ok": True,
            "base_url": self.config.base_url,
            "searches_visible": len(data) if isinstance(data, list) else None,
            "lossless_only": self.config.lossless_only,
            "minimum_lossy_bitrate_kbps": self.config.minimum_lossy_bitrate_kbps,
        }

    async def search_album(
        self,
        *,
        artist: str,
        album: str,
        timeout_seconds: int | None = None,
        max_candidates: int = 20,
    ) -> tuple[str, list[AlbumCandidate], dict[str, Any]]:
        timeout_seconds = timeout_seconds or self.config.search_timeout
        payload = {
            "searchText": f"{artist} {album}",
            "fileLimit": 10000,
            "filterResponses": True,
            "maximumPeerQueueLength": 1000000,
            "minimumPeerUploadSpeed": 0,
            "minimumResponseFileCount": self.config.minimum_tracks,
            "responseLimit": self.config.result_limit,
            "searchTimeout": timeout_seconds,
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
        candidates = build_album_candidates(
            payload=result,
            artist=artist,
            album=album,
            search_id=search_id,
            preferred_formats=self.config.preferred_formats,
            minimum_tracks=self.config.minimum_tracks,
            lossless_only=self.config.lossless_only,
            minimum_lossy_bitrate_kbps=self.config.minimum_lossy_bitrate_kbps,
        )
        return (
            search_id,
            candidates[:max_candidates],
            result if isinstance(result, dict) else {"result": result},
        )

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
        requested_id = str(uuid.uuid4())
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
                "externalId": external_id
                or stable_id("album", candidate.candidate_id),
            },
        }
        result = await self.request(
            "POST", "/api/v0/transfers/downloads/batches", json=payload
        )
        output = result if isinstance(result, dict) else {"result": result}
        output.setdefault("requestedBatchId", requested_id)
        output.setdefault("destination", destination)
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
