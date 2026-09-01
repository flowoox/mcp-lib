from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    AgentObservation,
    AgentStatusSummary,
    AlertLevelCount,
    AlertSummary,
    ApiInfoObservation,
    ManagerLogComponentSummary,
    ManagerStatusObservation,
    VulnerabilitySeverityCount,
    VulnerabilitySummary,
)

_AGENT_ID_RE = re.compile(r"^[0-9]{1,16}$")
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_AGENT_STATUSES = frozenset({"active", "disconnected", "pending", "never_connected"})
_LOG_LEVEL_FIELDS = ("all", "info", "warning", "error", "critical", "debug")


class WazuhClientError(RuntimeError):
    """Raised when a fixed Wazuh adapter rejects or cannot parse a response."""


class WazuhRateLimitError(WazuhClientError):
    """Raised on backend HTTP 429 without retry amplification."""

    def __init__(self, backend: str, retry_after_seconds: int | None) -> None:
        self.retry_after_seconds = retry_after_seconds
        message = f"{backend} rate limit reached"
        if retry_after_seconds is not None:
            message += f"; retry after {retry_after_seconds} seconds"
        super().__init__(message)


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(parsed, 0)


def _optional_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= parsed <= 10:
        return None
    return parsed


def _server_data(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise WazuhClientError("Wazuh server response must be a JSON object")
    error = payload.get("error")
    if error not in {None, 0, "0"}:
        raise WazuhClientError("Wazuh server returned an application error")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise WazuhClientError("Wazuh server response omitted its data object")
    return data


def _affected_items(payload: Any) -> tuple[list[Mapping[str, Any]], int]:
    data = _server_data(payload)
    raw_items = data.get("affected_items", [])
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes, bytearray)):
        raise WazuhClientError("Wazuh server affected_items must be a JSON array")
    items: list[Mapping[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, Mapping):
            raise WazuhClientError("Wazuh server affected item must be a JSON object")
        items.append(item)
    total = _nonnegative_int(data.get("total_affected_items", len(items)))
    if total < len(items):
        raise WazuhClientError("Wazuh server total_affected_items is smaller than returned items")
    return items, total


def _agent_id(value: Any) -> str:
    normalized = _text(value, max_length=17).strip()
    if not _AGENT_ID_RE.fullmatch(normalized):
        raise WazuhClientError("Wazuh returned an invalid agent identifier")
    return normalized


def _project_agent(row: Mapping[str, Any]) -> dict[str, Any]:
    os_data = row.get("os")
    if not isinstance(os_data, Mapping):
        os_data = {}
    return AgentObservation(
        agent_id=_agent_id(row.get("id")),
        name=_text(row.get("name"), max_length=128),
        status=_text(row.get("status"), max_length=32).casefold(),
        os_name=_text(os_data.get("name"), max_length=128),
        os_platform=_text(os_data.get("platform"), max_length=64),
        os_version=_text(os_data.get("version"), max_length=128),
        agent_version=_text(row.get("version"), max_length=64),
        node_name=_text(row.get("node_name"), max_length=128),
        last_keepalive=_text(row.get("lastKeepAlive"), max_length=64),
        group_config_status=_text(row.get("group_config_status"), max_length=64),
    ).model_dump(mode="json")


def _hits_total(payload: Mapping[str, Any]) -> int:
    hits = payload.get("hits")
    if not isinstance(hits, Mapping):
        raise WazuhClientError("Wazuh indexer response omitted hits")
    total = hits.get("total", 0)
    if isinstance(total, Mapping):
        return _nonnegative_int(total.get("value"))
    return _nonnegative_int(total)


class WazuhServerReadOnlyTransport:
    """Fixed Wazuh server API adapter using the built-in readonly role."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.server_read_only_attested:
            raise ValueError(
                "WAZUH_SERVER_BACKEND_READ_ONLY=true and WAZUH_SERVER_BACKEND_ROLE=readonly "
                "are required"
            )
        if not settings.server_configured:
            raise ValueError(
                "WAZUH_SERVER_API_BASE_URL, WAZUH_SERVER_USERNAME and "
                "WAZUH_SERVER_PASSWORD are required"
            )
        self.settings = settings
        self._transport = transport
        self._jwt: str | None = None
        parsed = urlsplit(settings.wazuh_server_api_base_url)
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())

    @property
    def read_only(self) -> bool:
        return self.settings.server_read_only_attested

    async def _authenticate(self, *, timeout_seconds: float, max_response_bytes: int) -> str:
        if self._jwt:
            return self._jwt
        async with httpx.AsyncClient(
            base_url=f"{self.settings.wazuh_server_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.wazuh_server_tls_verify,
            auth=httpx.BasicAuth(
                self.settings.wazuh_server_username,
                self.settings.wazuh_server_password.get_secret_value(),
            ),
            headers={
                "Accept": "application/json",
                "User-Agent": "flowoox-mcp-wazuh/0.1",
            },
        ) as client, client.stream(
            "POST",
            "security/user/authenticate",
            params={"raw": "true"},
        ) as response:
            if 300 <= response.status_code < 400:
                raise WazuhClientError("Wazuh server authentication redirects are not allowed")
            if response.status_code == 429:
                raw_retry = response.headers.get("Retry-After", "").strip()
                retry_after = int(raw_retry) if raw_retry.isdecimal() else None
                raise WazuhRateLimitError("Wazuh server", retry_after)
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Wazuh server authentication failed with status {response.status_code}"
                )
            body = bytearray()
            auth_limit = min(max_response_bytes, 16_384)
            async for chunk in response.aiter_bytes():
                if len(chunk) > auth_limit - len(body):
                    raise WazuhClientError("Wazuh authentication response exceeded its byte limit")
                body.extend(chunk)
        try:
            raw = body.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise WazuhClientError("Wazuh authentication returned invalid UTF-8") from exc
        if raw.startswith('"') and raw.endswith('"'):
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise WazuhClientError("Wazuh authentication returned invalid JSON") from exc
            raw = decoded if isinstance(decoded, str) else ""
        if not 20 <= len(raw) <= 16_000 or any(ord(character) < 33 for character in raw):
            raise WazuhClientError("Wazuh authentication returned an invalid JWT")
        self._jwt = raw
        return raw

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        if path.startswith("/") or ".." in path:
            raise ValueError("Wazuh server adapter path must be a fixed relative API path")
        token = await self._authenticate(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        async with httpx.AsyncClient(
            base_url=f"{self.settings.wazuh_server_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.wazuh_server_tls_verify,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "flowoox-mcp-wazuh/0.1",
            },
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise WazuhClientError("Wazuh server redirects are not allowed")
            if response.status_code == 429:
                raw_retry = response.headers.get("Retry-After", "").strip()
                retry_after = int(raw_retry) if raw_retry.isdecimal() else None
                raise WazuhRateLimitError("Wazuh server", retry_after)
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Wazuh server GET operation failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise WazuhClientError("Wazuh server response exceeded the byte limit")
                body.extend(chunk)
        try:
            return json.loads(body), len(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WazuhClientError("Wazuh server returned invalid JSON") from exc

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("Wazuh server operation received unsupported parameters")
        return dict(query.parameters)

    def _offset(self, cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not cursor.startswith("offset:"):
            raise ValueError("unsupported Wazuh pagination cursor")
        raw = cursor.removeprefix("offset:")
        if not raw.isdecimal() or len(raw) > 6:
            raise ValueError("invalid Wazuh pagination cursor")
        offset = int(raw)
        if not 0 <= offset <= self.settings.wazuh_max_offset:
            raise ValueError("Wazuh pagination cursor exceeds the configured offset limit")
        return offset

    async def _api_info(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if not isinstance(payload, Mapping):
            raise WazuhClientError("Wazuh API info must be a JSON object")
        item = ApiInfoObservation(
            title=_text(payload.get("title"), max_length=64),
            api_version=_text(payload.get("api_version"), max_length=32),
            revision=_text(payload.get("revision"), max_length=32),
        ).model_dump(mode="json")
        return ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def _agent_summary(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "agents/summary",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        data = _server_data(payload)
        status = data.get("status")
        if not isinstance(status, Mapping):
            raise WazuhClientError("Wazuh agent summary omitted status counts")
        active = _nonnegative_int(status.get("active"))
        disconnected = _nonnegative_int(status.get("disconnected"))
        pending = _nonnegative_int(status.get("pending"))
        never_connected = _nonnegative_int(status.get("never_connected"))
        item = AgentStatusSummary(
            active=active,
            disconnected=disconnected,
            pending=pending,
            never_connected=never_connected,
            total=active + disconnected + pending + never_connected,
        ).model_dump(mode="json")
        return ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def _agents(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"status"}))
        offset = self._offset(query.page.cursor)
        params: list[tuple[str, str]] = [
            ("offset", str(offset)),
            ("limit", str(query.page.limit)),
            (
                "select",
                "id,name,status,os.name,os.platform,os.version,version,node_name,"
                "lastKeepAlive,group_config_status",
            ),
        ]
        requested_status = parameters.get("status")
        if requested_status not in {None, ""}:
            if not isinstance(requested_status, str) or requested_status not in _AGENT_STATUSES:
                raise ValueError("status is not in the fixed Wazuh status allowlist")
            params.append(("status", requested_status))
        payload, payload_bytes = await self._request_json(
            "agents",
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_items, total = _affected_items(payload)
        if len(raw_items) > query.page.limit:
            raise WazuhClientError("Wazuh server returned more agents than requested")
        rows = [_project_agent(row) for row in raw_items]
        next_offset = offset + len(rows)
        cursor = None
        if next_offset < total and rows and next_offset <= self.settings.wazuh_max_offset:
            cursor = f"offset:{next_offset}"
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None or next_offset < total,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def _manager_status(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "manager/status",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_items, _ = _affected_items(payload)
        source = raw_items[0] if raw_items else {}
        daemons: dict[str, str] = {}
        for key in sorted(source):
            if len(daemons) >= 32:
                break
            key_text = str(key)
            if not _SAFE_COMPONENT_RE.fullmatch(key_text):
                continue
            value = source[key]
            if isinstance(value, (str, int, float, bool)) and value is not None:
                daemons[key_text] = _text(value, max_length=32)
        item = ManagerStatusObservation(daemons=daemons).model_dump(mode="json")
        return ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def _manager_logs_summary(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "manager/logs/summary",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_items, _ = _affected_items(payload)
        rows: list[dict[str, Any]] = []
        for wrapper in raw_items[:32]:
            for component, raw_counts in wrapper.items():
                component_name = str(component)
                if not _SAFE_COMPONENT_RE.fullmatch(component_name):
                    continue
                if not isinstance(raw_counts, Mapping):
                    continue
                counts = {field: _nonnegative_int(raw_counts.get(field)) for field in _LOG_LEVEL_FIELDS}
                rows.append(
                    ManagerLogComponentSummary(
                        component=component_name,
                        total=counts["all"],
                        info=counts["info"],
                        warning=counts["warning"],
                        error=counts["error"],
                        critical=counts["critical"],
                        debug=counts["debug"],
                    ).model_dump(mode="json")
                )
                if len(rows) >= 32:
                    break
            if len(rows) >= 32:
                break
        return ReadOnlyPage(
            items=rows,
            truncated=len(raw_items) > len(rows),
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "wazuh.api.info":
            return await self._api_info(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "wazuh.agents.summary":
            return await self._agent_summary(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "wazuh.agents.list":
            return await self._agents(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "wazuh.manager.status":
            return await self._manager_status(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "wazuh.manager.logs.summary":
            return await self._manager_logs_summary(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("Wazuh server operation is not in the fixed read-only allowlist")


class WazuhIndexerReadOnlyTransport:
    """Fixed aggregation-only Wazuh indexer adapter."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.indexer_read_only_attested:
            raise ValueError(
                "WAZUH_INDEXER_BACKEND_READ_ONLY=true and a deployment-owned read role "
                "attestation are required"
            )
        if not settings.indexer_configured:
            raise ValueError(
                "WAZUH_INDEXER_API_BASE_URL, WAZUH_INDEXER_USERNAME and "
                "WAZUH_INDEXER_PASSWORD are required"
            )
        self.settings = settings
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.indexer_read_only_attested

    async def _search(
        self,
        path: str,
        *,
        body: Mapping[str, Any],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        if path not in {
            "wazuh-alerts*/_search",
            "wazuh-states-vulnerabilities-*/_search",
        }:
            raise PermissionError("Wazuh indexer path is not in the fixed search allowlist")
        encoded = json.dumps(body, separators=(",", ":")).encode()
        if len(encoded) > 16_384:
            raise ValueError("generated Wazuh indexer query exceeded the outbound byte limit")
        async with httpx.AsyncClient(
            base_url=f"{self.settings.wazuh_indexer_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.wazuh_indexer_tls_verify,
            auth=httpx.BasicAuth(
                self.settings.wazuh_indexer_username,
                self.settings.wazuh_indexer_password.get_secret_value(),
            ),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "flowoox-mcp-wazuh/0.1",
            },
        ) as client, client.stream("POST", path, content=encoded) as response:
            if 300 <= response.status_code < 400:
                raise WazuhClientError("Wazuh indexer redirects are not allowed")
            if response.status_code == 429:
                raw_retry = response.headers.get("Retry-After", "").strip()
                retry_after = int(raw_retry) if raw_retry.isdecimal() else None
                raise WazuhRateLimitError("Wazuh indexer", retry_after)
            if response.status_code != 200:
                raise WazuhClientError(
                    f"Wazuh indexer search failed with status {response.status_code}"
                )
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(raw):
                    raise WazuhClientError("Wazuh indexer response exceeded the byte limit")
                raw.extend(chunk)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WazuhClientError("Wazuh indexer returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise WazuhClientError("Wazuh indexer response must be a JSON object")
        if payload.get("timed_out") is True:
            raise WazuhClientError("Wazuh indexer search timed out")
        return payload, len(raw)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("Wazuh indexer operation received unsupported parameters")
        return dict(query.parameters)

    async def _alerts_summary(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"window_minutes", "minimum_rule_level"}))
        window = parameters.get("window_minutes", 60)
        minimum_level = parameters.get("minimum_rule_level", 3)
        if isinstance(window, bool) or not isinstance(window, int):
            raise ValueError("window_minutes must be an integer")
        if not 15 <= window <= self.settings.wazuh_max_alert_window_minutes:
            raise ValueError("window_minutes exceeds the configured Wazuh alert window")
        if isinstance(minimum_level, bool) or not isinstance(minimum_level, int):
            raise ValueError("minimum_rule_level must be an integer")
        if not 0 <= minimum_level <= 16:
            raise ValueError("minimum_rule_level must be between 0 and 16")
        body = {
            "size": 0,
            "track_total_hits": True,
            "_source": False,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": f"now-{window}m", "lte": "now"}}},
                        {"range": {"rule.level": {"gte": minimum_level}}},
                    ]
                }
            },
            "aggs": {
                "by_level": {
                    "terms": {
                        "field": "rule.level",
                        "size": 17,
                        "order": {"_key": "asc"},
                    }
                }
            },
        }
        payload, payload_bytes = await self._search(
            "wazuh-alerts*/_search",
            body=body,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        aggregations = payload.get("aggregations")
        if not isinstance(aggregations, Mapping):
            raise WazuhClientError("Wazuh alert summary omitted aggregations")
        by_level = aggregations.get("by_level")
        buckets = by_level.get("buckets") if isinstance(by_level, Mapping) else None
        if not isinstance(buckets, Sequence) or isinstance(buckets, (str, bytes, bytearray)):
            raise WazuhClientError("Wazuh alert level aggregation omitted buckets")
        levels: list[AlertLevelCount] = []
        for bucket in buckets[:17]:
            if not isinstance(bucket, Mapping):
                raise WazuhClientError("Wazuh alert aggregation bucket must be an object")
            level = _nonnegative_int(bucket.get("key"))
            if level > 16:
                continue
            levels.append(
                AlertLevelCount(level=level, count=_nonnegative_int(bucket.get("doc_count")))
            )
        item = AlertSummary(
            total=_hits_total(payload),
            window_minutes=window,
            minimum_rule_level=minimum_level,
            by_level=levels,
        ).model_dump(mode="json")
        return ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def _vulnerabilities_summary(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        body = {
            "size": 0,
            "track_total_hits": True,
            "_source": False,
            "aggs": {
                "by_severity": {
                    "terms": {
                        "field": "vulnerability.severity",
                        "size": 8,
                        "order": {"_count": "desc"},
                    }
                },
                "max_cvss_base": {"max": {"field": "vulnerability.score.base"}},
            },
        }
        payload, payload_bytes = await self._search(
            "wazuh-states-vulnerabilities-*/_search",
            body=body,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        aggregations = payload.get("aggregations")
        if not isinstance(aggregations, Mapping):
            raise WazuhClientError("Wazuh vulnerability summary omitted aggregations")
        by_severity = aggregations.get("by_severity")
        buckets = by_severity.get("buckets") if isinstance(by_severity, Mapping) else None
        if not isinstance(buckets, Sequence) or isinstance(buckets, (str, bytes, bytearray)):
            raise WazuhClientError("Wazuh vulnerability severity aggregation omitted buckets")
        severities: list[VulnerabilitySeverityCount] = []
        for bucket in buckets[:8]:
            if not isinstance(bucket, Mapping):
                raise WazuhClientError("Wazuh vulnerability aggregation bucket must be an object")
            severity = _text(bucket.get("key"), max_length=32).strip()
            if not severity:
                continue
            severities.append(
                VulnerabilitySeverityCount(
                    severity=severity,
                    count=_nonnegative_int(bucket.get("doc_count")),
                )
            )
        max_cvss = aggregations.get("max_cvss_base")
        max_cvss_value = max_cvss.get("value") if isinstance(max_cvss, Mapping) else None
        item = VulnerabilitySummary(
            total=_hits_total(payload),
            by_severity=severities,
            max_cvss_base=_optional_float(max_cvss_value),
        ).model_dump(mode="json")
        return ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.wazuh_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "wazuh.alerts.summary":
            return await self._alerts_summary(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "wazuh.vulnerabilities.summary":
            return await self._vulnerabilities_summary(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("Wazuh indexer operation is not in the fixed read-only allowlist")
