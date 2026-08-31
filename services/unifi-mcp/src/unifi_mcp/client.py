from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    ApplicationObservation,
    ClientObservation,
    DeviceObservation,
    DeviceStatisticsObservation,
    RadioStatistics,
    SiteObservation,
)


class UniFiClientError(RuntimeError):
    """Raised when the fixed UniFi adapter rejects or cannot parse a response."""


class UniFiRateLimitError(UniFiClientError):
    """Raised on UniFi HTTP 429 without automatic retries."""

    def __init__(self, retry_after_seconds: int | None) -> None:
        self.retry_after_seconds = retry_after_seconds
        message = "UniFi rate limit reached"
        if retry_after_seconds is not None:
            message += f"; retry after {retry_after_seconds} seconds"
        super().__init__(message)


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _integer(value: Any, *, minimum: int | None = None) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and result < minimum:
        return None
    return result


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _uuid(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UUID")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc
    return str(parsed)


def _string_list(value: Any, *, max_items: int = 16, max_length: int = 64) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [_text(item, max_length=max_length) for item in list(value)[:max_items]]


def _project_application(row: Mapping[str, Any]) -> dict[str, Any]:
    return ApplicationObservation(
        application_version=_text(row.get("applicationVersion"), max_length=64)
    ).model_dump(mode="json")


def _project_site(row: Mapping[str, Any]) -> dict[str, Any]:
    return SiteObservation(
        site_id=_uuid(row.get("id"), field="site_id"),
        name=_text(row.get("name"), max_length=256),
    ).model_dump(mode="json")


def _project_device(row: Mapping[str, Any]) -> dict[str, Any]:
    interfaces = row.get("interfaces")
    port_count = 0
    radio_count = 0
    interface_names: list[str] = []
    if isinstance(interfaces, Mapping):
        ports = interfaces.get("ports")
        radios = interfaces.get("radios")
        port_count = min(len(ports), 10_000) if isinstance(ports, list) else 0
        radio_count = min(len(radios), 1_000) if isinstance(radios, list) else 0
        interface_names = [
            name for name in ("ports", "radios") if isinstance(interfaces.get(name), list)
        ]
    else:
        interface_names = _string_list(interfaces)
    features = row.get("features")
    if isinstance(features, Mapping):
        feature_names = [
            str(name)[:64]
            for name, enabled in list(features.items())[:16]
            if enabled is not None
        ]
    else:
        feature_names = _string_list(features)
    return DeviceObservation(
        device_id=_uuid(row.get("id"), field="device_id"),
        name=_text(row.get("name"), max_length=256),
        model=_text(row.get("model"), max_length=128),
        state=_text(row.get("state"), max_length=64),
        supported=_boolean(row.get("supported")),
        firmware_version=_text(row.get("firmwareVersion"), max_length=128),
        firmware_updatable=_boolean(row.get("firmwareUpdatable")),
        features=feature_names,
        interfaces=interface_names,
        adopted_at=_text(row.get("adoptedAt"), max_length=64),
        provisioned_at=_text(row.get("provisionedAt"), max_length=64),
        has_uplink=isinstance(row.get("uplink"), Mapping),
        port_count=port_count,
        radio_count=radio_count,
    ).model_dump(mode="json")


def _project_statistics(row: Mapping[str, Any]) -> dict[str, Any]:
    uplink = row.get("uplink")
    uplink_map = uplink if isinstance(uplink, Mapping) else {}
    interfaces = row.get("interfaces")
    interfaces_map = interfaces if isinstance(interfaces, Mapping) else {}
    radios_value = interfaces_map.get("radios")
    radios: list[RadioStatistics] = []
    if isinstance(radios_value, list):
        for raw in radios_value[:32]:
            if not isinstance(raw, Mapping):
                continue
            radios.append(
                RadioStatistics(
                    frequency_ghz=_text(raw.get("frequencyGHz"), max_length=16),
                    tx_retries_pct=_number(raw.get("txRetriesPct")),
                )
            )
    return DeviceStatisticsObservation(
        uptime_seconds=_integer(row.get("uptimeSec"), minimum=0),
        last_heartbeat_at=_text(row.get("lastHeartbeatAt"), max_length=64),
        next_heartbeat_at=_text(row.get("nextHeartbeatAt"), max_length=64),
        load_average_1m=_number(row.get("loadAverage1Min")),
        load_average_5m=_number(row.get("loadAverage5Min")),
        load_average_15m=_number(row.get("loadAverage15Min")),
        cpu_utilization_pct=_number(row.get("cpuUtilizationPct")),
        memory_utilization_pct=_number(row.get("memoryUtilizationPct")),
        uplink_tx_rate_bps=_integer(uplink_map.get("txRateBps"), minimum=0),
        uplink_rx_rate_bps=_integer(uplink_map.get("rxRateBps"), minimum=0),
        radios=radios,
    ).model_dump(mode="json")


def _project_client(row: Mapping[str, Any]) -> dict[str, Any]:
    access = row.get("access")
    access_map = access if isinstance(access, Mapping) else {}
    return ClientObservation(
        client_id=_uuid(row.get("id"), field="client_id"),
        client_type=_text(row.get("type"), max_length=64),
        connected_at=_text(row.get("connectedAt"), max_length=64),
        access_type=_text(access_map.get("type"), max_length=64),
        access_authorized=_boolean(access_map.get("authorized")),
    ).model_dump(mode="json")


class UniFiReadOnlyTransport:
    """Official UniFi Network Integration API adapter with fixed GET-only operations."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.unifi_backend_read_only:
            raise ValueError(
                "UNIFI_BACKEND_READ_ONLY=true is required and must attest that the API key "
                "belongs to a deployment-managed read-only UniFi identity"
            )
        if not settings.configured:
            raise ValueError("UNIFI_API_BASE_URL and UNIFI_API_KEY are required")
        self.settings = settings
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.unifi_backend_read_only

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        if path.startswith("/") or ".." in path:
            raise ValueError("UniFi adapter path must be a fixed relative API path")
        api_key = self.settings.unifi_api_key.get_secret_value()
        async with httpx.AsyncClient(
            base_url=f"{self.settings.unifi_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.unifi_tls_verify,
            headers={
                "Accept": "application/json",
                "X-API-Key": api_key,
                "User-Agent": "flowoox-mcp-unifi/0.1",
            },
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise UniFiClientError("UniFi redirects are not allowed")
            if response.status_code == 429:
                raw_retry = response.headers.get("Retry-After", "").strip()
                retry_after = int(raw_retry) if raw_retry.isdecimal() else None
                raise UniFiRateLimitError(retry_after)
            if response.status_code != 200:
                raise UniFiClientError(
                    f"UniFi GET operation failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise UniFiClientError("UniFi response exceeded the configured byte limit")
                body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UniFiClientError("UniFi returned invalid JSON") from exc
        return payload, len(body)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("UniFi operation received unsupported parameters")
        return dict(query.parameters)

    def _offset(self, cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not cursor.startswith("offset:"):
            raise ValueError("unsupported UniFi pagination cursor")
        raw = cursor.removeprefix("offset:")
        if not raw.isdecimal() or len(raw) > 6:
            raise ValueError("invalid UniFi offset cursor")
        offset = int(raw)
        if offset > self.settings.unifi_max_offset:
            raise ValueError("UniFi pagination cursor exceeds the configured offset limit")
        return offset

    def _page(
        self,
        payload: Any,
        *,
        requested_offset: int,
        requested_limit: int,
        projector: Any,
        payload_bytes: int,
    ) -> ReadOnlyPage:
        if not isinstance(payload, Mapping):
            raise UniFiClientError("UniFi list response must be a JSON object")
        data = payload.get("data")
        if not isinstance(data, list):
            raise UniFiClientError("UniFi page must contain a data array")
        returned_offset = _integer(payload.get("offset"), minimum=0)
        returned_limit = _integer(payload.get("limit"), minimum=0)
        count = _integer(payload.get("count"), minimum=0)
        total = _integer(payload.get("totalCount"), minimum=0)
        if None in {returned_offset, returned_limit, count, total}:
            raise UniFiClientError("UniFi page omitted required pagination metadata")
        if returned_offset != requested_offset:
            raise UniFiClientError("UniFi returned an unexpected page offset")
        if returned_limit > requested_limit or len(data) > requested_limit or count != len(data):
            raise UniFiClientError("UniFi returned more rows than requested or invalid count metadata")
        rows = []
        for raw_row in data:
            if not isinstance(raw_row, Mapping):
                raise UniFiClientError("UniFi page row must be a JSON object")
            rows.append(projector(raw_row))
        next_offset = requested_offset + len(data)
        next_cursor = None
        if next_offset < total and next_offset <= self.settings.unifi_max_offset:
            next_cursor = f"offset:{next_offset}"
        return ReadOnlyPage(
            items=rows,
            next_cursor=next_cursor,
            truncated=next_cursor is not None or next_offset < total,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.unifi_cache_max_age_seconds),
        )

    async def _list(
        self,
        query: ReadOnlyQuery,
        *,
        path: str,
        projector: Any,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        offset = self._offset(query.page.cursor)
        payload, payload_bytes = await self._request_json(
            path,
            params=(("offset", str(offset)), ("limit", str(query.page.limit))),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return self._page(
            payload,
            requested_offset=offset,
            requested_limit=query.page.limit,
            projector=projector,
            payload_bytes=payload_bytes,
        )

    async def _single(
        self,
        *,
        path: str,
        projector: Any,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        payload, payload_bytes = await self._request_json(
            path,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if not isinstance(payload, Mapping):
            raise UniFiClientError("UniFi detail response must be a JSON object")
        return ReadOnlyPage(
            items=[projector(payload)],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.unifi_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "unifi.application.info":
            self._parameters(query, frozenset())
            return await self._single(
                path="v1/info",
                projector=_project_application,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "unifi.sites.list":
            self._parameters(query, frozenset())
            return await self._list(
                query,
                path="v1/sites",
                projector=_project_site,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )

        scoped_operations = {
            "unifi.devices.list",
            "unifi.devices.get",
            "unifi.devices.statistics.latest",
            "unifi.clients.list",
            "unifi.clients.get",
        }
        if query.operation not in scoped_operations:
            raise PermissionError("UniFi operation is not in the fixed read-only transport allowlist")
        parameters = self._parameters(query, frozenset({"site_id", "device_id", "client_id"}))
        site_id = _uuid(parameters.get("site_id"), field="site_id")
        if query.operation == "unifi.devices.list":
            if set(parameters) != {"site_id"}:
                raise ValueError("unifi.devices.list accepts only site_id")
            return await self._list(
                query,
                path=f"v1/sites/{site_id}/devices",
                projector=_project_device,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation in {"unifi.devices.get", "unifi.devices.statistics.latest"}:
            if set(parameters) != {"site_id", "device_id"}:
                raise ValueError("device detail operations require site_id and device_id")
            device_id = _uuid(parameters.get("device_id"), field="device_id")
            path = f"v1/sites/{site_id}/devices/{device_id}"
            if query.operation == "unifi.devices.statistics.latest":
                path = f"{path}/statistics/latest"
            return await self._single(
                path=path,
                projector=(
                    _project_statistics
                    if query.operation == "unifi.devices.statistics.latest"
                    else _project_device
                ),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "unifi.clients.list":
            if set(parameters) != {"site_id"}:
                raise ValueError("unifi.clients.list accepts only site_id")
            return await self._list(
                query,
                path=f"v1/sites/{site_id}/clients",
                projector=_project_client,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if set(parameters) != {"site_id", "client_id"}:
            raise ValueError("unifi.clients.get requires site_id and client_id")
        client_id = _uuid(parameters.get("client_id"), field="client_id")
        return await self._single(
            path=f"v1/sites/{site_id}/clients/{client_id}",
            projector=_project_client,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
