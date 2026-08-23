from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx
from mcp_common.operations import StrictModel
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings, normalize_base_url
from .endpoints import ENDPOINTS, ApiScope, FortiGateEndpoint
from .observations import project_response


class FortiGateClientError(RuntimeError):
    pass


class VdomParameters(StrictModel):
    vdom: str


class FortiGateApiTransport:
    """GET-only adapter for a fixed, projected FortiOS REST API surface."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not settings.fortigate_backend_read_only:
            raise ValueError(
                "FORTIGATE_BACKEND_READ_ONLY=true is required to attest a read-only API identity"
            )
        token = settings.fortigate_api_token.get_secret_value().strip()
        if not token:
            raise ValueError("FORTIGATE_API_TOKEN must be configured")
        self.settings = settings
        self.base_url = normalize_base_url(settings.fortigate_base_url)
        self._verify = settings.tls_verify_value()
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.fortigate_backend_read_only

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.settings.fortigate_api_token.get_secret_value()}",
            "User-Agent": "flowoox-mcp-fortigate/0.1",
        }

    async def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers,
            transport=self._transport,
            verify=self._verify,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        ) as client, client.stream("GET", path, params=params) as response:
            if 300 <= response.status_code < 400:
                raise FortiGateClientError("FortiGate API redirects are not allowed")
            if response.status_code >= 400:
                raise FortiGateClientError(
                    f"FortiGate API GET {path} failed with status {response.status_code}"
                )
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise FortiGateClientError("FortiGate API returned invalid Content-Length") from exc
                if declared < 0 or declared > max_response_bytes:
                    raise FortiGateClientError("FortiGate API response exceeds the configured byte limit")
            payload = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(payload):
                    raise FortiGateClientError("FortiGate API response exceeds the configured byte limit")
                payload.extend(chunk)
        try:
            decoded = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FortiGateClientError("FortiGate API returned invalid JSON") from exc
        if not isinstance(decoded, Mapping):
            raise FortiGateClientError("FortiGate API response must be a JSON object")
        if str(decoded.get("status", "success")).casefold() == "error":
            raise FortiGateClientError("FortiGate API reported an application-level error")
        return decoded, len(payload)

    @staticmethod
    def _offset(cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not cursor.isdecimal():
            raise ValueError("FortiGate cursor is invalid")
        value = int(cursor)
        if value < 0 or value > 1_000_000:
            raise ValueError("FortiGate cursor is outside the supported range")
        return value

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        try:
            endpoint = FortiGateEndpoint(query.operation.removeprefix("fortigate."))
        except ValueError as exc:
            raise PermissionError("FortiGate operation is not implemented by the fixed GET adapter") from exc
        spec = ENDPOINTS[endpoint]
        offset = self._offset(query.page.cursor)
        params: dict[str, str] = {}
        if spec.scope is ApiScope.VDOM:
            requested = VdomParameters.model_validate(query.parameters).vdom
            params["vdom"] = self.settings.resolve_vdom(requested)
        elif query.parameters:
            raise ValueError("global FortiGate operations do not accept VDOM parameters")
        if spec.scope is ApiScope.GLOBAL:
            params["global"] = "1"
        if spec.collection:
            params["count"] = str(query.page.limit)
            params["start"] = str(offset)
        elif query.page.cursor is not None:
            raise ValueError("single-object FortiGate operations do not accept a cursor")
        if spec.format_fields:
            params["format"] = "|".join(spec.format_fields)

        payload, payload_bytes = await self._get_json(
            spec.path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        projected = project_response(endpoint, payload, limit=query.page.limit)
        items = projected.pop("items", None)
        normalized_items = items if isinstance(items, list) else [projected]

        truncated = False
        next_cursor: str | None = None
        if spec.collection:
            returned = len(normalized_items)
            matched_count = payload.get("matched_count")
            limit_reached = payload.get("limit_reached") is True
            if isinstance(matched_count, int):
                truncated = offset + returned < matched_count
            else:
                truncated = limit_reached or returned == query.page.limit
            if truncated and returned:
                next_cursor = str(offset + returned)

        cache_seconds = 3 if endpoint is FortiGateEndpoint.SYSTEM_STATUS else self.settings.fortigate_cache_max_age_seconds
        return ReadOnlyPage(
            items=normalized_items,
            next_cursor=next_cursor,
            truncated=truncated,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=cache_seconds),
        )
