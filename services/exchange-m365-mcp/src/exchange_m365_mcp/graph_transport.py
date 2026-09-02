from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from typing import Any

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import ServiceHealthObservation, ServiceIssueObservation

_GRAPH_ORIGIN = "https://graph.microsoft.com"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class GraphTransportError(RuntimeError):
    """Raised when the fixed Microsoft Graph service-health adapter fails closed."""


def _text(value: Any, *, max_length: int = 256) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _issue_ref(value: Any) -> str:
    normalized = _text(value, max_length=128).strip().casefold()
    if not normalized:
        raise GraphTransportError("Microsoft Graph issue is missing a stable identifier")
    return f"issue:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]}"


class MicrosoftGraphServiceHealthTransport:
    """Microsoft Graph v1.0 adapter limited to ServiceHealth.Read.All observations."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.m365_graph_backend_read_only:
            raise ValueError(
                "M365_GRAPH_BACKEND_READ_ONLY=true is required for the Graph reader identity"
            )
        if not settings.m365_graph_service_health_permission_attested:
            raise ValueError(
                "M365_GRAPH_SERVICE_HEALTH_PERMISSION_ATTESTED=true is required for the Graph app"
            )
        if not settings.graph_configured:
            raise ValueError(
                "M365_GRAPH_TENANT_ID, M365_GRAPH_CLIENT_ID and M365_GRAPH_CLIENT_SECRET are required"
            )
        self.settings = settings
        self._transport = transport
        self._token: str = ""
        self._token_expires_at = 0.0
        self._token_lock = asyncio.Lock()

    @property
    def read_only(self) -> bool:
        return self.settings.m365_graph_backend_read_only

    async def _bounded_json(
        self,
        response: httpx.Response,
        *,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        if 300 <= response.status_code < 400:
            raise GraphTransportError("Microsoft endpoint redirects are not allowed")
        if response.status_code != 200:
            raise GraphTransportError(
                f"Microsoft endpoint observation failed with status {response.status_code}"
            )
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(chunk) > max_response_bytes - len(body):
                raise GraphTransportError("Microsoft response exceeded the configured byte limit")
            body.extend(chunk)
        try:
            return json.loads(body), len(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GraphTransportError("Microsoft endpoint returned invalid JSON") from exc

    async def _access_token(self, *, timeout_seconds: float) -> str:
        loop = asyncio.get_running_loop()
        if self._token and loop.time() < self._token_expires_at:
            return self._token
        async with self._token_lock:
            now = loop.time()
            if self._token and now < self._token_expires_at:
                return self._token
            token_url = (
                f"https://login.microsoftonline.com/{self.settings.m365_graph_tenant_id}/"
                "oauth2/v2.0/token"
            )
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
            ) as client, client.stream(
                "POST",
                token_url,
                data={
                    "client_id": self.settings.m365_graph_client_id,
                    "client_secret": self.settings.m365_graph_client_secret.get_secret_value(),
                    "scope": _GRAPH_SCOPE,
                    "grant_type": "client_credentials",
                },
                headers={"Accept": "application/json"},
            ) as response:
                payload, _ = await self._bounded_json(response, max_response_bytes=64 * 1024)
            if not isinstance(payload, Mapping):
                raise GraphTransportError("Microsoft token response must be an object")
            token = payload.get("access_token")
            if not isinstance(token, str) or not token:
                raise GraphTransportError("Microsoft token response omitted an access token")
            try:
                expires_in = int(payload.get("expires_in", 300))
            except (TypeError, ValueError):
                expires_in = 300
            self._token = token
            self._token_expires_at = now + max(30, min(expires_in - 60, 3_300))
            return token

    @staticmethod
    def _validate_query(query: ReadOnlyQuery) -> None:
        if query.parameters:
            raise ValueError("Graph service-health operations do not accept free-form parameters")
        if query.page.cursor is not None:
            raise ValueError("Graph Observe v1 is intentionally first-page-only")

    async def _get(
        self,
        path: str,
        *,
        params: tuple[tuple[str, str], ...] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        token = await self._access_token(timeout_seconds=timeout_seconds)
        async with httpx.AsyncClient(
            base_url=f"{_GRAPH_ORIGIN}/v1.0/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "flowoox-mcp-exchange-m365/0.1",
            },
        ) as client, client.stream("GET", path, params=params) as response:
            return await self._bounded_json(response, max_response_bytes=max_response_bytes)

    @staticmethod
    def _rows(payload: Any) -> tuple[list[Mapping[str, Any]], bool]:
        if not isinstance(payload, Mapping):
            raise GraphTransportError("Microsoft Graph collection response must be an object")
        value = payload.get("value")
        if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
            raise GraphTransportError("Microsoft Graph collection omitted an object-array value")
        return value, isinstance(payload.get("@odata.nextLink"), str)

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._validate_query(query)
        if query.operation == "m365.service_health.list":
            payload, payload_bytes = await self._get(
                "admin/serviceAnnouncement/healthOverviews",
                params=(("$select", "service,status"), ("$top", str(query.page.limit + 1))),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            rows, has_next = self._rows(payload)
            projected = [
                ServiceHealthObservation(
                    service=_text(row.get("service"), max_length=128),
                    status=_text(row.get("status"), max_length=64),
                ).model_dump(mode="json")
                for row in rows[: query.page.limit]
            ]
        elif query.operation == "m365.exchange_issues.list":
            payload, payload_bytes = await self._get(
                "admin/serviceAnnouncement/issues",
                params=(
                    ("$filter", "service eq 'Exchange Online'"),
                    (
                        "$select",
                        "id,service,status,classification,origin,feature,featureGroup,"
                        "startDateTime,endDateTime,lastModifiedDateTime",
                    ),
                    ("$top", str(query.page.limit + 1)),
                ),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            rows, has_next = self._rows(payload)
            exchange_rows = [
                row for row in rows if _text(row.get("service"), max_length=128) == "Exchange Online"
            ]
            projected = [
                ServiceIssueObservation(
                    issue_ref=_issue_ref(row.get("id")),
                    service="Exchange Online",
                    status=_text(row.get("status"), max_length=64),
                    classification=_text(row.get("classification"), max_length=64),
                    origin=_text(row.get("origin"), max_length=64),
                    feature=_text(row.get("feature"), max_length=160),
                    feature_group=_text(row.get("featureGroup"), max_length=160),
                    start_date_time=_text(row.get("startDateTime"), max_length=64),
                    end_date_time=_text(row.get("endDateTime"), max_length=64),
                    last_modified_date_time=_text(
                        row.get("lastModifiedDateTime"), max_length=64
                    ),
                ).model_dump(mode="json")
                for row in exchange_rows[: query.page.limit]
            ]
            has_next = has_next or len(exchange_rows) > query.page.limit
        else:
            raise PermissionError("Graph operation is not implemented by the fixed adapter")
        return ReadOnlyPage(
            items=projected,
            truncated=has_next or len(rows) > query.page.limit,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.graph_cache_max_age_seconds),
        )
