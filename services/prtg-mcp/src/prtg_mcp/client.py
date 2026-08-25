from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    ChannelObservation,
    DeviceObservation,
    HealthMetric,
    HealthStatusObservation,
    HistoricSample,
    MessageObservation,
    Scalar,
    SensorObservation,
)

_TABLE_COLUMNS = {
    "prtg.devices.list": (
        "devices",
        "objid,probe,group,device,status,message,priority,dependency,active,parentid,"
        "upsens,downsens,downacksens,partialdownsens,warnsens,pausedsens,unusualsens,"
        "undefinedsens,totalsens",
    ),
    "prtg.sensors.list": (
        "sensors",
        "objid,probe,group,device,sensor,type,status,message,lastvalue,priority,dependency,"
        "active,parentid,lastcheck,interval",
    ),
    "prtg.alarms.list": (
        "sensors",
        "objid,probe,group,device,sensor,type,status,message,lastvalue,priority,dependency,"
        "active,parentid,lastcheck,interval",
    ),
    "prtg.channels.list": ("channels", "objid,name,lastvalue"),
    "prtg.messages.list": (
        "messages",
        "objid,datetime,parent,type,name,status,message,priority",
    ),
}
_ALARM_STATUS_IDS = (4, 5, 10, 13, 14)
_MESSAGE_WINDOWS = frozenset({"today", "yesterday", "7days"})
_HISTORIC_AVERAGES = frozenset({0, 60, 300, 900, 3600, 14400, 86400})
_DATE_FORMAT = "%Y-%m-%d-%H-%M-%S"
_SENSOR_COUNT_FIELDS = (
    "upsens",
    "downsens",
    "downacksens",
    "partialdownsens",
    "warnsens",
    "pausedsens",
    "unusualsens",
    "undefinedsens",
    "totalsens",
)


class PrtgClientError(RuntimeError):
    """Raised when the fixed PRTG read-only adapter rejects or cannot parse a response."""


def _text(row: Mapping[str, Any], key: str, *, max_length: int) -> str:
    raw_key = f"{key}_raw"
    value = row.get(raw_key, row.get(key, ""))
    if value is None:
        return ""
    return str(value)[:max_length]


def _integer(row: Mapping[str, Any], key: str, *, minimum: int = 0) -> int | None:
    value = row.get(f"{key}_raw", row.get(key))
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = int(float(str(value).strip().strip('"')))
    except (TypeError, ValueError):
        return None
    return result if result >= minimum else None


def _boolean(row: Mapping[str, Any], key: str) -> bool | None:
    value = row.get(f"{key}_raw", row.get(key))
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().strip('"').lower()
        if normalized in {"1", "true", "yes", "active"}:
            return True
        if normalized in {"0", "false", "no", "inactive"}:
            return False
    return None


def _scalar(value: Any, *, max_length: int = 2048) -> Scalar:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:max_length]
    return str(value)[:max_length]


def _object_id(row: Mapping[str, Any]) -> int:
    value = _integer(row, "objid")
    if value is None:
        raise PrtgClientError("PRTG table row omitted a valid object ID")
    return value


def _project_device(row: Mapping[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for field in _SENSOR_COUNT_FIELDS:
        value = _integer(row, field)
        if value is not None:
            counts[field] = value
    return DeviceObservation(
        object_id=_object_id(row),
        probe=_text(row, "probe", max_length=512),
        group=_text(row, "group", max_length=512),
        device=_text(row, "device", max_length=512),
        status=_text(row, "status", max_length=128),
        status_id=_integer(row, "status"),
        message=_text(row, "message", max_length=2048),
        priority=_integer(row, "priority"),
        dependency=_text(row, "dependency", max_length=512),
        active=_boolean(row, "active"),
        parent_id=_integer(row, "parentid"),
        sensor_counts=counts,
    ).model_dump(mode="json")


def _project_sensor(row: Mapping[str, Any]) -> dict[str, Any]:
    return SensorObservation(
        object_id=_object_id(row),
        probe=_text(row, "probe", max_length=512),
        group=_text(row, "group", max_length=512),
        device=_text(row, "device", max_length=512),
        sensor=_text(row, "sensor", max_length=512),
        sensor_type=_text(row, "type", max_length=256),
        status=_text(row, "status", max_length=128),
        status_id=_integer(row, "status"),
        message=_text(row, "message", max_length=2048),
        last_value=_text(row, "lastvalue", max_length=1024),
        priority=_integer(row, "priority"),
        dependency=_text(row, "dependency", max_length=512),
        active=_boolean(row, "active"),
        parent_id=_integer(row, "parentid"),
        last_check=_text(row, "lastcheck", max_length=128),
        interval=_text(row, "interval", max_length=128),
    ).model_dump(mode="json")


def _project_channel(row: Mapping[str, Any]) -> dict[str, Any]:
    return ChannelObservation(
        object_id=_object_id(row),
        name=_text(row, "name", max_length=512),
        last_value=_text(row, "lastvalue", max_length=1024),
    ).model_dump(mode="json")


def _project_message(row: Mapping[str, Any]) -> dict[str, Any]:
    return MessageObservation(
        object_id=_object_id(row),
        datetime=_text(row, "datetime", max_length=128),
        parent=_text(row, "parent", max_length=512),
        event_type=_text(row, "type", max_length=256),
        name=_text(row, "name", max_length=512),
        status=_text(row, "status", max_length=128),
        message=_text(row, "message", max_length=2048),
        priority=_integer(row, "priority"),
    ).model_dump(mode="json")


def _health_metrics(payload: Mapping[str, Any], limit: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(name: str, value: Any) -> None:
        if len(items) >= limit:
            return
        items.append(
            HealthMetric(name=name[:128], value=_scalar(value, max_length=1024)).model_dump(
                mode="json"
            )
        )

    for key, value in payload.items():
        if len(items) >= limit:
            break
        name = str(key)[:128]
        if value is None or isinstance(value, (str, bool, int, float)):
            add(name, value)
            continue
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                if child_value is None or isinstance(child_value, (str, bool, int, float)):
                    add(f"{name}.{child_key}", child_value)
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for index, entry in enumerate(value[:32]):
                if isinstance(entry, Mapping):
                    metric_name = entry.get("name") or entry.get("Name") or f"{name}.{index}"
                    metric_value = entry.get("value", entry.get("Value", entry.get("state", entry.get("State"))))
                    if metric_value is not None and not isinstance(metric_value, (Mapping, list, tuple)):
                        add(str(metric_name), metric_value)
                elif entry is None or isinstance(entry, (str, bool, int, float)):
                    add(f"{name}.{index}", entry)
    return items


def _historic_samples(rows: Sequence[Any], limit: int) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for raw_row in rows[:limit]:
        if not isinstance(raw_row, Mapping):
            raise PrtgClientError("PRTG historic data row must be a JSON object")
        timestamp = _text(raw_row, "datetime", max_length=128)
        values: dict[str, Scalar] = {}
        visible_keys = [
            str(key)
            for key in raw_row
            if str(key) not in {"datetime", "datetime_raw"} and not str(key).endswith("_raw")
        ]
        for key in visible_keys[:32]:
            value = raw_row.get(f"{key}_raw", raw_row.get(key))
            if value is None or isinstance(value, (str, bool, int, float)):
                values[key[:128]] = _scalar(value, max_length=1024)
        samples.append(HistoricSample(datetime=timestamp, values=values).model_dump(mode="json"))
    return samples


class PrtgReadOnlyTransport:
    """PRTG HTTP API adapter with a fixed GET-only operation surface."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        historic_interval_seconds: float = 12.0,
    ) -> None:
        if not settings.prtg_backend_read_only:
            raise ValueError("PRTG_BACKEND_READ_ONLY=true is required for the PRTG reader identity")
        if not settings.configured:
            raise ValueError("PRTG_BASE_URL and PRTG_API_KEY are required")
        if historic_interval_seconds < 0:
            raise ValueError("historic_interval_seconds must be non-negative")
        self.settings = settings
        self._transport = transport
        self._historic_interval_seconds = historic_interval_seconds
        self._historic_lock = asyncio.Lock()
        self._next_historic_at = 0.0

    @property
    def read_only(self) -> bool:
        return self.settings.prtg_backend_read_only

    async def _historic_rate_slot(self) -> None:
        async with self._historic_lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            delay = max(0.0, self._next_historic_at - now)
            if delay:
                await asyncio.sleep(delay)
            self._next_historic_at = loop.time() + self._historic_interval_seconds

    async def _request(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[int, bytes]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.settings.prtg_api_key.get_secret_value()}",
            "User-Agent": "flowoox-mcp-prtg/0.1",
        }
        async with httpx.AsyncClient(
            base_url=self.settings.prtg_base_url,
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.prtg_tls_verify,
            headers=headers,
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise PrtgClientError("PRTG redirects are not allowed")
            if response.status_code not in accepted_statuses:
                raise PrtgClientError(
                    f"PRTG GET {path} failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise PrtgClientError("PRTG response exceeded the configured byte limit")
                body.extend(chunk)
        return response.status_code, bytes(body)

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        _, body = await self._request(
            path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrtgClientError("PRTG returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise PrtgClientError("PRTG response must be a JSON object")
        if payload.get("error") or str(payload.get("state", "")).lower() == "error":
            raise PrtgClientError("PRTG reported an API error")
        return payload, len(body)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("PRTG operation received unsupported parameters")
        return dict(query.parameters)

    @staticmethod
    def _positive_object_id(value: Any, field_name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{field_name} must be a positive integer")
        return value

    @staticmethod
    def _optional_object_id(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("object_id must be a positive integer when provided")
        return value

    @staticmethod
    def _cursor_offset(cursor: str | None) -> int:
        if cursor is None:
            return 0
        if len(cursor) > 16 or not cursor.isascii() or not cursor.isdecimal():
            raise ValueError("PRTG cursor must be a bounded decimal offset")
        value = int(cursor)
        if value > 10_000_000:
            raise ValueError("PRTG cursor offset is too large")
        return value

    async def _table(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        content, columns = _TABLE_COLUMNS[query.operation]
        allowed = {"sensor_id"} if query.operation == "prtg.channels.list" else {"object_id"}
        if query.operation == "prtg.messages.list":
            allowed.add("window")
        parameters = self._parameters(query, frozenset(allowed))
        offset = self._cursor_offset(query.page.cursor)
        params: list[tuple[str, str]] = [
            ("content", content),
            ("columns", columns),
            ("count", str(query.page.limit)),
            ("start", str(offset)),
        ]
        if query.operation == "prtg.channels.list":
            sensor_id = self._positive_object_id(parameters.get("sensor_id"), "sensor_id")
            params.append(("id", str(sensor_id)))
        else:
            object_id = self._optional_object_id(parameters.get("object_id"))
            if object_id is not None:
                params.append(("id", str(object_id)))
        if query.operation == "prtg.alarms.list":
            params.extend(("filter_status", str(status)) for status in _ALARM_STATUS_IDS)
            params.append(("sortby", "priority"))
        if query.operation == "prtg.messages.list":
            window = parameters.get("window", "today")
            if window not in _MESSAGE_WINDOWS:
                raise ValueError("message window must be today, yesterday, or 7days")
            params.append(("filter_drel", str(window)))

        payload, payload_bytes = await self._request_json(
            "/api/table.json",
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_rows = payload.get(content, [])
        if not isinstance(raw_rows, list):
            raise PrtgClientError(f"PRTG {content} response must contain a list")
        if len(raw_rows) > query.page.limit:
            raise PrtgClientError("PRTG table returned more rows than requested")
        project = {
            "prtg.devices.list": _project_device,
            "prtg.sensors.list": _project_sensor,
            "prtg.alarms.list": _project_sensor,
            "prtg.channels.list": _project_channel,
            "prtg.messages.list": _project_message,
        }[query.operation]
        rows: list[dict[str, Any]] = []
        for row in raw_rows:
            if not isinstance(row, Mapping):
                raise PrtgClientError("PRTG table row must be a JSON object")
            rows.append(project(row))
        total = payload.get("treesize")
        total_count = int(total) if isinstance(total, int) and total >= 0 else None
        has_more = (
            offset + len(rows) < total_count
            if total_count is not None
            else len(rows) == query.page.limit
        )
        return ReadOnlyPage(
            items=rows,
            next_cursor=str(offset + len(rows)) if has_more and rows else None,
            truncated=has_more,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.prtg_cache_max_age_seconds),
        )

    async def _health_status(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        status, body = await self._request(
            "/api/healthstatus.json",
            timeout_seconds=timeout_seconds,
            max_response_bytes=min(max_response_bytes, 16_384),
            accepted_statuses=frozenset({200, 503}),
        )
        item = HealthStatusObservation(healthy=status == 200, status_code=status).model_dump(
            mode="json"
        )
        return ReadOnlyPage(
            items=[item],
            payload_bytes=len(body),
            cache_hint=CacheHint(max_age_seconds=5),
        )

    async def _health_data(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"maxage_seconds"}))
        maxage = parameters.get("maxage_seconds", self.settings.prtg_health_max_age_seconds)
        if isinstance(maxage, bool) or not isinstance(maxage, int) or not 30 <= maxage <= 900:
            raise ValueError("maxage_seconds must be an integer from 30 through 900")
        payload, payload_bytes = await self._request_json(
            "/api/health.json",
            params=(("maxage", str(maxage)),),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        items = _health_metrics(payload, query.page.limit)
        return ReadOnlyPage(
            items=items,
            truncated=len(items) == query.page.limit and len(payload) > len(items),
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=min(maxage, 300)),
        )

    async def _historic(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(
            query,
            frozenset({"sensor_id", "start", "end", "average_seconds"}),
        )
        sensor_id = self._positive_object_id(parameters.get("sensor_id"), "sensor_id")
        start_value = parameters.get("start")
        end_value = parameters.get("end")
        average = parameters.get("average_seconds", 0)
        if not isinstance(start_value, str) or not isinstance(end_value, str):
            raise ValueError("start and end must use yyyy-mm-dd-hh-mm-ss")
        try:
            start = datetime.strptime(start_value, _DATE_FORMAT)
            end = datetime.strptime(end_value, _DATE_FORMAT)
        except ValueError as exc:
            raise ValueError("start and end must use yyyy-mm-dd-hh-mm-ss") from exc
        if end <= start:
            raise ValueError("historic end must be later than start")
        if isinstance(average, bool) or not isinstance(average, int) or average not in _HISTORIC_AVERAGES:
            raise ValueError("average_seconds is not in the fixed safe averaging allowlist")
        window = end - start
        configured_window = timedelta(hours=self.settings.prtg_historic_max_window_hours)
        if window > configured_window:
            raise ValueError("historic window exceeds the deployment load-safety limit")
        if average < 3600 and window > timedelta(days=40):
            raise ValueError("sub-hour PRTG historic requests cannot exceed 40 days")
        if window > timedelta(days=500):
            raise ValueError("PRTG historic requests cannot exceed 500 days")

        await self._historic_rate_slot()
        payload, payload_bytes = await self._request_json(
            "/api/historicdata.json",
            params=(
                ("id", str(sensor_id)),
                ("avg", str(average)),
                ("sdate", start_value),
                ("edate", end_value),
                ("usecaption", "1"),
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        rows = payload.get("histdata", [])
        if not isinstance(rows, list):
            raise PrtgClientError("PRTG historic response must contain a histdata list")
        samples = _historic_samples(rows, query.page.limit)
        truncated = len(rows) > query.page.limit
        return ReadOnlyPage(
            items=samples,
            truncated=truncated,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=60),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation in _TABLE_COLUMNS:
            return await self._table(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "prtg.system.health-status":
            return await self._health_status(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "prtg.system.health-data":
            return await self._health_data(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "prtg.historic.sensor":
            return await self._historic(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("PRTG operation is not implemented by the fixed read-only adapter")
