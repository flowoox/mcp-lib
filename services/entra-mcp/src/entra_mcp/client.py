from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .endpoints import ENDPOINTS, EntraEndpoint
from .observations import project_collection


class EntraClientError(RuntimeError):
    pass


class GraphReadOnlyTransport:
    """App-only Microsoft Graph adapter restricted to fixed GET endpoints."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not settings.entra_backend_read_only:
            raise ValueError("ENTRA_BACKEND_READ_ONLY=true is required for the Graph reader identity")
        if not settings.configured:
            raise ValueError("ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET are required")
        self.settings = settings
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = asyncio.Lock()

    @property
    def read_only(self) -> bool:
        return self.settings.entra_backend_read_only

    async def _token_value(self, timeout_seconds: float) -> str:
        loop = asyncio.get_running_loop()
        if self._token and loop.time() < self._token_expires_at - 60:
            return self._token
        async with self._token_lock:
            now = loop.time()
            if self._token and now < self._token_expires_at - 60:
                return self._token
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    self.settings.token_url,
                    data={
                        "client_id": self.settings.entra_client_id,
                        "client_secret": self.settings.entra_client_secret.get_secret_value(),
                        "scope": f"{self.settings.graph_origin}/.default",
                        "grant_type": "client_credentials",
                    },
                    headers={"Accept": "application/json"},
                )
            if 300 <= response.status_code < 400:
                raise EntraClientError("Microsoft identity token endpoint redirects are not allowed")
            if response.status_code >= 400:
                raise EntraClientError(
                    f"Microsoft identity token request failed with status {response.status_code}"
                )
            if len(response.content) > 65_536:
                raise EntraClientError("Microsoft identity token response exceeded its byte limit")
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise EntraClientError("Microsoft identity token endpoint returned invalid JSON") from exc
            token = payload.get("access_token") if isinstance(payload, Mapping) else None
            expires_in = payload.get("expires_in") if isinstance(payload, Mapping) else None
            if not isinstance(token, str) or not token:
                raise EntraClientError("Microsoft identity token response omitted access_token")
            if not isinstance(expires_in, (int, float)) or expires_in <= 0:
                expires_in = 300
            self._token = token
            self._token_expires_at = loop.time() + min(float(expires_in), 86_400.0)
            return token

    def _cursor_skiptoken(self, endpoint: EntraEndpoint, cursor: str | None) -> str | None:
        if cursor is None:
            return None
        if len(cursor) > 8_192:
            raise ValueError("Microsoft Graph cursor is too large")
        parsed = urlsplit(cursor)
        spec = ENDPOINTS[endpoint]
        expected = urlsplit(self.settings.graph_origin)
        if parsed.scheme != expected.scheme or parsed.netloc != expected.netloc or parsed.path != spec.path:
            raise ValueError("Microsoft Graph cursor does not match the fixed endpoint")
        params = parse_qs(parsed.query, keep_blank_values=False)
        allowed = {"$skiptoken", "$select", "$top"}
        if any(key not in allowed for key in params):
            raise ValueError("Microsoft Graph cursor contains unsupported query parameters")
        expected_select = ",".join(spec.select_fields)
        selected = params.get("$select")
        if selected and selected != [expected_select]:
            raise ValueError("Microsoft Graph cursor changed the fixed field projection")
        values = params.get("$skiptoken")
        if not values or len(values) != 1 or not values[0]:
            raise ValueError("Microsoft Graph cursor is missing a skip token")
        return values[0]

    async def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        token = await self._token_value(timeout_seconds)
        async with httpx.AsyncClient(
            base_url=self.settings.graph_origin,
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "flowoox-mcp-entra/0.1",
            },
        ) as client, client.stream("GET", path, params=params) as response:
            if 300 <= response.status_code < 400:
                raise EntraClientError("Microsoft Graph redirects are not allowed")
            if response.status_code >= 400:
                raise EntraClientError(f"Microsoft Graph GET {path} failed with status {response.status_code}")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise EntraClientError("Microsoft Graph response exceeded the configured byte limit")
                body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EntraClientError("Microsoft Graph returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise EntraClientError("Microsoft Graph response must be a JSON object")
        return payload, len(body)

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.parameters:
            raise ValueError("Entra fixed read-only operations do not accept arbitrary parameters")
        try:
            endpoint = EntraEndpoint(query.operation.removeprefix("entra."))
        except ValueError as exc:
            raise PermissionError("Entra operation is not implemented by the fixed Graph adapter") from exc
        spec = ENDPOINTS[endpoint]
        params = {
            "$select": ",".join(spec.select_fields),
            "$top": str(query.page.limit),
        }
        skiptoken = self._cursor_skiptoken(endpoint, query.page.cursor)
        if skiptoken is not None:
            params["$skiptoken"] = skiptoken
        payload, payload_bytes = await self._get_json(
            spec.path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        projected = project_collection(endpoint, payload, limit=query.page.limit)
        items = projected["items"]
        next_link = payload.get("@odata.nextLink")
        next_cursor = None
        if next_link is not None:
            if not isinstance(next_link, str):
                raise EntraClientError("Microsoft Graph nextLink must be a string")
            self._cursor_skiptoken(endpoint, next_link)
            next_cursor = next_link
        return ReadOnlyPage(
            items=items,
            next_cursor=next_cursor,
            truncated=next_cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.entra_cache_max_age_seconds),
        )
