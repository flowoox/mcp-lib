from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal
from urllib.parse import quote

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import CheckmkVersionObservation, HostObservation, ServiceObservation

_HOST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
_HOST_COLUMNS = (
    "name",
    "state",
    "acknowledged",
    "in_downtime",
    "is_flapping",
    "stale",
    "last_check",
    "last_state_change",
)
_SERVICE_COLUMNS = (
    "host_name",
    "description",
    "state",
    "acknowledged",
    "in_downtime",
    "is_flapping",
    "stale",
    "last_check",
    "last_state_change",
)


class CheckmkClientError(RuntimeError):
    """Raised when the fixed Checkmk adapter rejects or cannot parse a response."""


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:max_length]


def _integer(value: Any) -> int | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _host_state_label(value: int | None) -> str:
    return {0: "UP", 1: "DOWN", 2: "UNREACHABLE", 3: "PENDING"}.get(value, "OTHER")


def _service_state_label(value: int | None) -> str:
    return {0: "OK", 1: "WARN", 2: "CRIT", 3: "UNKNOWN", 4: "PENDING"}.get(
        value, "OTHER"
    )


def _extensions(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("extensions", {})
    if not isinstance(value, Mapping):
        raise CheckmkClientError("Checkmk monitoring object extensions must be a JSON object")
    return value


def _host_name(value: Any) -> str:
    normalized = _text(value, max_length=255).strip()
    if not _HOST_NAME_RE.fullmatch(normalized):
        raise ValueError("host_name must be a bounded Checkmk host identifier")
    return normalized


def _project_host(row: Mapping[str, Any]) -> dict[str, Any]:
    ext = _extensions(row)
    name = _host_name(ext.get("name") or row.get("id"))
    state = _integer(ext.get("state"))
    return HostObservation(
        host_name=name,
        state=state,
        state_label=_host_state_label(state),
        acknowledged=_boolean(ext.get("acknowledged")),
        in_downtime=_boolean(ext.get("in_downtime")),
        is_flapping=_boolean(ext.get("is_flapping")),
        stale=_boolean(ext.get("stale")),
        last_check=_integer(ext.get("last_check")),
        last_state_change=_integer(ext.get("last_state_change")),
    ).model_dump(mode="json")


def _project_service(row: Mapping[str, Any]) -> dict[str, Any]:
    ext = _extensions(row)
    host_name = _host_name(ext.get("host_name"))
    description = _text(ext.get("description"), max_length=512).strip()
    if not description:
        raise CheckmkClientError("Checkmk service object omitted its description")
    state = _integer(ext.get("state"))
    return ServiceObservation(
        host_name=host_name,
        description=description,
        state=state,
        state_label=_service_state_label(state),
        acknowledged=_boolean(ext.get("acknowledged")),
        in_downtime=_boolean(ext.get("in_downtime")),
        is_flapping=_boolean(ext.get("is_flapping")),
        stale=_boolean(ext.get("stale")),
        last_check=_integer(ext.get("last_check")),
        last_state_change=_integer(ext.get("last_state_change")),
    ).model_dump(mode="json")


def _collection_rows(payload: Any) -> list[Mapping[str, Any]]:
    if not isinstance(payload, Mapping):
        raise CheckmkClientError("Checkmk collection response must be a JSON object")
    value = payload.get("value")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CheckmkClientError("Checkmk collection response omitted its value array")
    rows: list[Mapping[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise CheckmkClientError("Checkmk collection row must be a JSON object")
        rows.append(row)
    return rows


def _version_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise CheckmkClientError("Checkmk version response must be a JSON object")
    version = _text(payload.get("version"), max_length=128)
    edition = _text(payload.get("edition"), max_length=128)
    versions = payload.get("versions")
    if isinstance(versions, Mapping):
        if not version:
            version = _text(
                versions.get("checkmk") or versions.get("check_mk") or versions.get("version"),
                max_length=128,
            )
        if not edition:
            edition = _text(versions.get("edition"), max_length=128)
    return CheckmkVersionObservation(version=version, edition=edition).model_dump(mode="json")


def _problem_query() -> dict[str, str]:
    return {"op": "!=", "left": "state", "right": "0"}


class CheckmkReadOnlyTransport:
    """Stable Checkmk REST 1.0 adapter with fixed query-only operations."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.checkmk_backend_read_only:
            raise ValueError(
                "CHECKMK_BACKEND_READ_ONLY=true is required for the Checkmk reader identity"
            )
        if not settings.configured:
            raise ValueError(
                "CHECKMK_API_BASE_URL, CHECKMK_USERNAME, CHECKMK_AUTOMATION_SECRET and "
                "CHECKMK_BACKEND_ROLE are required"
            )
        username = settings.checkmk_username.strip()
        role = settings.checkmk_backend_role.strip()
        secret = settings.checkmk_automation_secret.get_secret_value()
        if any(character.isspace() for character in username) or any(
            character in "\r\n" for character in username + secret + role
        ):
            raise ValueError("Checkmk backend identity attestation contains unsafe whitespace")
        self.settings = settings
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.checkmk_backend_read_only

    async def _request_json(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        if path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("Checkmk adapter path must be a fixed relative API path")
        username = self.settings.checkmk_username.strip()
        secret = self.settings.checkmk_automation_secret.get_secret_value()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {username} {secret}",
            "User-Agent": "flowoox-mcp-checkmk/0.1",
        }
        if method == "POST":
            headers["Content-Type"] = "application/json"
        async with httpx.AsyncClient(
            base_url=f"{self.settings.checkmk_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.checkmk_tls_verify,
            headers=headers,
        ) as client, client.stream(method, path, json=body if method == "POST" else None) as response:
            if 300 <= response.status_code < 400:
                raise CheckmkClientError("Checkmk redirects are not allowed")
            if response.status_code != 200:
                raise CheckmkClientError(
                    f"Checkmk read operation failed with status {response.status_code}"
                )
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(raw):
                    raise CheckmkClientError(
                        "Checkmk response exceeded the configured byte limit"
                    )
                raw.extend(chunk)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckmkClientError("Checkmk returned invalid JSON") from exc
        return payload, len(raw)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("Checkmk operation received unsupported parameters")
        if query.page.cursor is not None:
            raise ValueError("Checkmk Observe v1 does not expose collection cursors")
        return dict(query.parameters)

    def _collection_page(
        self,
        rows: list[Mapping[str, Any]],
        *,
        limit: int,
        payload_bytes: int,
        projector: Any,
    ) -> ReadOnlyPage:
        projected = [projector(row) for row in rows[:limit]]
        return ReadOnlyPage(
            items=projected,
            truncated=len(rows) > limit,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.checkmk_cache_max_age_seconds),
        )

    async def _version(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "GET",
            "version",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return ReadOnlyPage(
            items=[_version_projection(payload)],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.checkmk_cache_max_age_seconds),
        )

    async def _problem_hosts(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "POST",
            "domain-types/host/collections/all",
            body={"columns": list(_HOST_COLUMNS), "query": _problem_query()},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return self._collection_page(
            _collection_rows(payload),
            limit=query.page.limit,
            payload_bytes=payload_bytes,
            projector=_project_host,
        )

    async def _problem_services(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self._parameters(query, frozenset())
        payload, payload_bytes = await self._request_json(
            "POST",
            "domain-types/service/collections/all",
            body={"columns": list(_SERVICE_COLUMNS), "query": _problem_query()},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return self._collection_page(
            _collection_rows(payload),
            limit=query.page.limit,
            payload_bytes=payload_bytes,
            projector=_project_service,
        )

    async def _host_problem_services(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"host_name"}))
        host_name = _host_name(parameters.get("host_name"))
        payload, payload_bytes = await self._request_json(
            "POST",
            f"objects/host/{quote(host_name, safe='')}/collections/services",
            body={"columns": list(_SERVICE_COLUMNS), "query": _problem_query()},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        rows = _collection_rows(payload)
        for row in rows:
            ext = _extensions(row)
            returned_host = ext.get("host_name")
            if returned_host not in {None, ""} and _host_name(returned_host) != host_name:
                raise CheckmkClientError("Checkmk returned a service for another host")
        return self._collection_page(
            rows,
            limit=query.page.limit,
            payload_bytes=payload_bytes,
            projector=_project_service,
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "checkmk.version.get":
            return await self._version(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "checkmk.problem_hosts.list":
            return await self._problem_hosts(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "checkmk.problem_services.list":
            return await self._problem_services(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "checkmk.host.problem_services":
            return await self._host_problem_services(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("Checkmk operation is not in the fixed read-only transport allowlist")
