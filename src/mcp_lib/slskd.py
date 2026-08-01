from __future__ import annotations

import asyncio
import uuid
from typing import Any
from urllib.parse import quote

import httpx

from .album_matcher import build_album_candidates
from .models import AlbumCandidate
from .utils import get_case_insensitive, safe_relative_destination, stable_id


class SlskdError(RuntimeError):
    pass


class SlskdClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout: float = 30,
        search_timeout: int = 15,
        result_limit: int = 200,
        minimum_tracks: int = 4,
        preferred_formats: list[str] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.search_timeout = search_timeout
        self.result_limit = result_limit
        self.minimum_tracks = minimum_tracks
        self.preferred_formats = preferred_formats or ["flac", "mp3"]

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=self.timeout,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
        if response.status_code >= 400:
            detail = response.text[:1000]
            raise SlskdError(f"slskd {method} {path} failed ({response.status_code}): {detail}")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return {"text": response.text}

    async def health(self) -> dict[str, Any]:
        searches = await self._request("GET", "/api/v0/searches")
        return {"ok": True, "searches_visible": len(searches) if isinstance(searches, list) else None}

    async def start_search(
        self,
        search_text: str,
        *,
        timeout_seconds: int | None = None,
        response_limit: int | None = None,
    ) -> dict[str, Any]:
        payload = {
            "searchText": search_text,
            "fileLimit": 10000,
            "filterResponses": True,
            "maximumPeerQueueLength": 1000000,
            "minimumPeerUploadSpeed": 0,
            "minimumResponseFileCount": self.minimum_tracks,
            "responseLimit": response_limit or self.result_limit,
            "searchTimeout": timeout_seconds or self.search_timeout,
        }
        result = await self._request("POST", "/api/v0/searches", json=payload)
        if not isinstance(result, dict):
            raise SlskdError(f"Unexpected search response: {type(result).__name__}")
        return result

    async def get_search(self, search_id: str, *, include_responses: bool = True) -> dict[str, Any]:
        result = await self._request(
            "GET",
            f"/api/v0/searches/{quote(search_id, safe='')}",
            params={"includeResponses": str(include_responses).lower()},
        )
        return result if isinstance(result, dict) else {"result": result}

    @staticmethod
    def _search_id(payload: dict[str, Any]) -> str:
        value = get_case_insensitive(payload, "id", "searchId")
        if value is None:
            raise SlskdError("slskd did not return a search id")
        return str(value)

    @staticmethod
    def _is_search_complete(payload: dict[str, Any]) -> bool:
        complete = get_case_insensitive(payload, "isComplete", "completed")
        if isinstance(complete, bool):
            return complete
        state = str(get_case_insensitive(payload, "state", "status", default="")).casefold()
        return state in {"completed", "complete", "stopped", "timedout", "timed_out"}

    async def search_album(
        self,
        *,
        artist: str,
        album: str,
        timeout_seconds: int | None = None,
        max_candidates: int = 20,
    ) -> tuple[str, list[AlbumCandidate], dict[str, Any]]:
        timeout_seconds = timeout_seconds or self.search_timeout
        search = await self.start_search(
            f"{artist} {album}",
            timeout_seconds=timeout_seconds,
        )
        search_id = self._search_id(search)
        deadline = asyncio.get_running_loop().time() + timeout_seconds + 5
        result = search
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(1)
            result = await self.get_search(search_id, include_responses=True)
            if self._is_search_complete(result):
                break

        candidates = build_album_candidates(
            payload=result,
            artist=artist,
            album=album,
            search_id=search_id,
            preferred_formats=self.preferred_formats,
            minimum_tracks=self.minimum_tracks,
        )
        return search_id, candidates[:max_candidates], result

    async def queue_album_candidate(
        self,
        candidate: AlbumCandidate,
        *,
        destination: str | None = None,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        destination = destination or safe_relative_destination(candidate.artist, candidate.album)
        requested_batch_id = str(uuid.uuid4())
        payload = {
            "id": requested_batch_id,
            "searchId": candidate.search_id,
            "username": candidate.username,
            "files": [
                {"filename": remote_file.filename, "size": remote_file.size}
                for remote_file in candidate.files
            ],
            "options": {
                "destination": destination,
                "externalId": external_id or stable_id("album", candidate.candidate_id),
            },
        }
        result = await self._request(
            "POST",
            "/api/v0/transfers/downloads/batches",
            json=payload,
        )
        if isinstance(result, dict):
            result.setdefault("requestedBatchId", requested_batch_id)
            return result
        return {
            "result": result,
            "request": payload,
            "requestedBatchId": requested_batch_id,
        }

    async def list_downloads(self) -> Any:
        return await self._request("GET", "/api/v0/transfers/downloads")

    async def get_download_batch(self, batch_id: str) -> Any:
        return await self._request(
            "GET",
            f"/api/v0/transfers/downloads/batches/{quote(batch_id, safe='')}",
        )

    async def browse_user(self, username: str) -> Any:
        return await self._request("GET", f"/api/v0/users/{quote(username, safe='')}/browse")

    @staticmethod
    def batch_id(payload: Any) -> str | None:
        if isinstance(payload, dict):
            value = get_case_insensitive(payload, "id", "batchId", "externalId")
            return str(value) if value is not None else None
        return None
