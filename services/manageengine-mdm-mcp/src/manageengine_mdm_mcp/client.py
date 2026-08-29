from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import CommandObservation, DeviceObservation, ScanStatusObservation

_DEVICE_ID_RE = re.compile(r"^[0-9]{1,32}$")
_PLATFORM_IDS = {"ios": "1", "android": "2", "windows": "3", "macos": "4", "tvos": "6"}


class ManageEngineMdmClientError(RuntimeError):
    """Raised when the fixed ManageEngine MDM adapter rejects or cannot parse a response."""


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None or value == "":
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


def _device_id(value: Any) -> str:
    normalized = _text(value, max_length=33).strip()
    if not _DEVICE_ID_RE.fullmatch(normalized):
        raise ValueError("device_id must be a bounded decimal identifier")
    return normalized


def _count(value: Any) -> int | None:
    parsed = _integer(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _project_device(row: Mapping[str, Any]) -> dict[str, Any]:
    summary = row.get("summary")
    summary_map = summary if isinstance(summary, Mapping) else {}
    return DeviceObservation(
        device_id=_device_id(row.get("device_id")),
        device_name=_text(row.get("device_name"), max_length=256),
        platform_type=_text(row.get("platform_type"), max_length=32).lower(),
        platform_type_id=_text(row.get("platform_type_id"), max_length=8),
        os_version=_text(row.get("os_version"), max_length=128),
        product_name=_text(row.get("product_name"), max_length=256),
        model=_text(row.get("model"), max_length=256),
        owned_by=_text(row.get("owned_by"), max_length=32),
        lost_mode_enabled=_boolean(row.get("is_lost_mode_enabled")),
        profile_count=_count(summary_map.get("profile_count")),
        app_count=_count(summary_map.get("app_count")),
        document_count=_count(summary_map.get("doc_count")),
        group_count=_count(summary_map.get("group_count")),
    ).model_dump(mode="json")


def _project_scan(device_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
    return ScanStatusObservation(
        device_id=device_id,
        status_code=_integer(row.get("status_code")),
        status_description=_text(row.get("status_description"), max_length=512),
        has_kb_url=bool(_text(row.get("kb_url"), max_length=2048).strip()),
    ).model_dump(mode="json")


def _project_command(expected_device_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
    returned_device_id = _device_id(row.get("device_id", expected_device_id))
    if returned_device_id != expected_device_id:
        raise ManageEngineMdmClientError("ManageEngine returned command history for another device")
    command_life = row.get("command_life")
    life_items = (
        command_life
        if isinstance(command_life, Sequence) and not isinstance(command_life, (str, bytes, bytearray))
        else []
    )
    latest: Mapping[str, Any] = {}
    for item in life_items[:64]:
        if isinstance(item, Mapping):
            latest = item
    return CommandObservation(
        device_id=returned_device_id,
        command_history_id=_text(row.get("command_history_id"), max_length=32),
        command_name=_text(row.get("command_name"), max_length=256),
        command_status=_integer(row.get("command_status")),
        managed_status=_integer(row.get("managed_status")),
        added_time=_text(row.get("added_time"), max_length=64),
        latest_status_code=_integer(latest.get("status_code")),
        latest_status_description=_text(latest.get("status_description"), max_length=512),
        latest_updated_time=_text(latest.get("updated_time"), max_length=64),
    ).model_dump(mode="json")


class ManageEngineMdmReadOnlyTransport:
    """ManageEngine MDM Plus REST adapter with a fixed GET-only observation surface."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.mdm_backend_read_only:
            raise ValueError("MDM_BACKEND_READ_ONLY=true is required for the MDM reader identity")
        if not settings.configured:
            raise ValueError("MDM_API_BASE_URL and MDM_API_TOKEN are required")
        self.settings = settings
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.mdm_backend_read_only

    def _headers(self) -> dict[str, str]:
        token = self.settings.mdm_api_token.get_secret_value()
        authorization = (
            f"Zoho-oauthtoken {token}" if self.settings.mdm_auth_mode == "cloud_oauth" else token
        )
        headers = {
            "Accept": "application/json",
            "Authorization": authorization,
            "User-Agent": "flowoox-mcp-manageengine-mdm/0.1",
        }
        if self.settings.mdm_customer_id:
            headers["X-CUSTOMER"] = self.settings.mdm_customer_id
        return headers

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        if path.startswith("/") or ".." in path:
            raise ValueError("MDM adapter path must be a fixed relative API path")
        async with httpx.AsyncClient(
            base_url=f"{self.settings.mdm_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.mdm_tls_verify,
            headers=self._headers(),
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise ManageEngineMdmClientError("ManageEngine MDM redirects are not allowed")
            if response.status_code != 200:
                raise ManageEngineMdmClientError(
                    f"ManageEngine MDM GET operation failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise ManageEngineMdmClientError(
                        "ManageEngine MDM response exceeded the configured byte limit"
                    )
                body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManageEngineMdmClientError("ManageEngine MDM returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ManageEngineMdmClientError("ManageEngine MDM response must be a JSON object")
        return payload, len(body)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("MDM operation received unsupported parameters")
        return dict(query.parameters)

    @staticmethod
    def _cursor_params(cursor: str | None) -> list[tuple[str, str]]:
        if cursor is None:
            return []
        if cursor.startswith("offset:"):
            raw = cursor.removeprefix("offset:")
            if not raw.isdecimal() or len(raw) > 10:
                raise ValueError("invalid MDM offset cursor")
            return [("offset", raw)]
        if cursor.startswith("skip:"):
            token = cursor.removeprefix("skip:")
            if not token or len(token) > 768 or any(character.isspace() for character in token):
                raise ValueError("invalid MDM skip-token cursor")
            return [("skip-token", token)]
        raise ValueError("unsupported MDM pagination cursor")

    @staticmethod
    def _next_cursor(payload: Mapping[str, Any], expected_path: str) -> str | None:
        paging = payload.get("paging")
        if not isinstance(paging, Mapping):
            return None
        raw_next = paging.get("next")
        if not raw_next:
            return None
        parsed = urlsplit(str(raw_next))
        if parsed.fragment or parsed.path != f"/{expected_path}":
            raise ManageEngineMdmClientError("MDM returned an invalid next-page link")
        params = parse_qs(parsed.query, keep_blank_values=True)
        skip_tokens = params.get("skip-token")
        if skip_tokens:
            token = skip_tokens[-1]
            if not token or len(token) > 768 or any(character.isspace() for character in token):
                raise ManageEngineMdmClientError("MDM returned an invalid skip-token")
            return f"skip:{token}"
        offsets = params.get("offset")
        if offsets:
            value = offsets[-1]
            if not value.isdecimal() or len(value) > 10:
                raise ManageEngineMdmClientError("MDM returned an invalid offset")
            return f"offset:{value}"
        raise ManageEngineMdmClientError("MDM next-page link omitted a supported cursor")

    async def _devices(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"platform", "search"}))
        params: list[tuple[str, str]] = [("limit", str(query.page.limit)), ("summary", "true")]
        params.extend(self._cursor_params(query.page.cursor))
        platform = parameters.get("platform")
        if platform is not None:
            if not isinstance(platform, str) or platform not in _PLATFORM_IDS:
                raise ValueError("platform is not in the fixed safe allowlist")
            params.append(("platform", _PLATFORM_IDS[platform]))
        search = parameters.get("search")
        if search is not None and search != "":
            if not isinstance(search, str):
                raise ValueError("search must be a string")
            normalized = search.strip()
            if not 1 <= len(normalized) <= 128 or any(ord(character) < 32 for character in normalized):
                raise ValueError("search must contain 1-128 printable characters")
            params.append(("search", normalized))

        path = "api/v1/mdm/devices"
        payload, payload_bytes = await self._request_json(
            path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_rows = payload.get("devices", [])
        if not isinstance(raw_rows, list):
            raise ManageEngineMdmClientError("MDM device-list response must contain a devices list")
        if len(raw_rows) > query.page.limit:
            raise ManageEngineMdmClientError("MDM returned more devices than requested")
        rows = []
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise ManageEngineMdmClientError("MDM device row must be a JSON object")
            rows.append(_project_device(raw_row))
        cursor = self._next_cursor(payload, path) if payload.get("paging") else None
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.mdm_cache_max_age_seconds),
        )

    async def _scan_status(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"device_id"}))
        device_id = _device_id(parameters.get("device_id"))
        payload, payload_bytes = await self._request_json(
            f"api/v1/mdm/devices/{device_id}/actions/scan",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return ReadOnlyPage(
            items=[_project_scan(device_id, payload)],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.mdm_cache_max_age_seconds),
        )

    async def _command_history(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"device_id", "days"}))
        device_id = _device_id(parameters.get("device_id"))
        days = parameters.get("days", 7)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 30:
            raise ValueError("days must be an integer between 1 and 30")
        path = f"api/v1/mdm/devices/{device_id}/commandhistory"
        params: list[tuple[str, str]] = [("limit", str(query.page.limit)), ("days", str(days))]
        params.extend(self._cursor_params(query.page.cursor))
        payload, payload_bytes = await self._request_json(
            path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_rows = payload.get("commands", [])
        if not isinstance(raw_rows, list):
            raise ManageEngineMdmClientError("MDM command-history response must contain a commands list")
        if len(raw_rows) > query.page.limit:
            raise ManageEngineMdmClientError("MDM returned more command records than requested")
        rows = []
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise ManageEngineMdmClientError("MDM command row must be a JSON object")
            rows.append(_project_command(device_id, raw_row))
        cursor = self._next_cursor(payload, path) if payload.get("paging") else None
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.mdm_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "manageengine_mdm.devices.list":
            return await self._devices(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "manageengine_mdm.devices.scan_status":
            return await self._scan_status(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "manageengine_mdm.devices.command_history":
            return await self._command_history(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("MDM operation is not in the fixed read-only transport allowlist")
