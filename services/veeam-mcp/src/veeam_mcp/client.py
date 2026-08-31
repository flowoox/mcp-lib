from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    BackupObservation,
    JobStateObservation,
    RepositoryStateObservation,
    RestorePointObservation,
    SessionObservation,
)


class VeeamClientError(RuntimeError):
    """Raised when the fixed Veeam adapter rejects or cannot parse a response."""


class VeeamRateLimitError(VeeamClientError):
    def __init__(self, retry_after_seconds: int | None) -> None:
        self.retry_after_seconds = retry_after_seconds
        message = "Veeam rate limit reached"
        if retry_after_seconds is not None:
            message += f"; retry after {retry_after_seconds} seconds"
        super().__init__(message)


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _integer(
    value: Any,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and result < minimum:
        return None
    if maximum is not None and result > maximum:
        return None
    return result


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_uuid(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return str(UUID(value))
    except ValueError:
        return ""


def _project_job_state(row: Mapping[str, Any]) -> dict[str, Any]:
    return JobStateObservation(
        job_id=_optional_uuid(row.get("id")),
        name=_text(row.get("name"), max_length=256),
        job_type=_text(row.get("type"), max_length=64),
        status=_text(row.get("status"), max_length=64),
        last_run=_text(row.get("lastRun"), max_length=64),
        last_result=_text(row.get("lastResult"), max_length=64),
        next_run=_text(row.get("nextRun"), max_length=64),
        objects_count=_integer(row.get("objectsCount"), minimum=0),
    ).model_dump(mode="json")


def _project_session(row: Mapping[str, Any]) -> dict[str, Any]:
    result_value = row.get("result")
    result = result_value if isinstance(result_value, Mapping) else {}
    return SessionObservation(
        session_id=_optional_uuid(row.get("id")),
        job_id=_optional_uuid(row.get("jobId")),
        name=_text(row.get("name"), max_length=256),
        session_type=_text(row.get("sessionType"), max_length=96),
        state=_text(row.get("state"), max_length=64),
        result=_text(result.get("result"), max_length=64),
        progress_percent=_integer(row.get("progressPercent"), minimum=0, maximum=100),
        creation_time=_text(row.get("creationTime"), max_length=64),
        end_time=_text(row.get("endTime"), max_length=64),
        canceled=_boolean(result.get("isCanceled")),
    ).model_dump(mode="json")


def _project_repository(row: Mapping[str, Any]) -> dict[str, Any]:
    return RepositoryStateObservation(
        repository_id=_optional_uuid(row.get("id")),
        name=_text(row.get("name"), max_length=256),
        repository_type=_text(row.get("type"), max_length=64),
        capacity_gb=_number(row.get("capacityGB")),
        free_gb=_number(row.get("freeGB")),
        used_space_gb=_number(row.get("usedSpaceGB")),
        is_online=_boolean(row.get("isOnline")),
        is_out_of_date=_boolean(row.get("isOutOfDate")),
    ).model_dump(mode="json")


def _project_backup(row: Mapping[str, Any]) -> dict[str, Any]:
    return BackupObservation(
        backup_id=_optional_uuid(row.get("id")),
        job_id=_optional_uuid(row.get("jobId")),
        name=_text(row.get("name"), max_length=256),
        platform_name=_text(row.get("platformName"), max_length=64),
        job_type=_text(row.get("jobType"), max_length=64),
        creation_time=_text(row.get("creationTime"), max_length=64),
        repository_id=_optional_uuid(row.get("repositoryId")),
    ).model_dump(mode="json")


def _project_restore_point(row: Mapping[str, Any]) -> dict[str, Any]:
    return RestorePointObservation(
        restore_point_id=_optional_uuid(row.get("id")),
        backup_id=_optional_uuid(row.get("backupId")),
        name=_text(row.get("name"), max_length=256),
        platform_name=_text(row.get("platformName"), max_length=64),
        restore_point_type=_text(row.get("type"), max_length=64),
        malware_status=_text(row.get("malwareStatus"), max_length=64),
        creation_time=_text(row.get("creationTime"), max_length=64),
    ).model_dump(mode="json")


class VeeamReadOnlyTransport:
    """VBR 13 REST adapter: exact OAuth login plus fixed GET-only observation routes."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.read_only_attested:
            raise ValueError(
                "VEEAM_BACKEND_READ_ONLY=true and VEEAM_BACKEND_ROLE='Backup Viewer' are required"
            )
        if not settings.configured:
            raise ValueError("VEEAM_API_BASE_URL, VEEAM_USERNAME and VEEAM_PASSWORD are required")
        self.settings = settings
        self._transport = transport
        self._token = ""
        self._token_valid_until = 0.0
        self._token_lock = asyncio.Lock()

    @property
    def read_only(self) -> bool:
        return self.settings.read_only_attested

    async def _access_token(self, *, timeout_seconds: float, max_response_bytes: int) -> str:
        if self._token and time.monotonic() < self._token_valid_until:
            return self._token
        async with self._token_lock:
            if self._token and time.monotonic() < self._token_valid_until:
                return self._token
            async with httpx.AsyncClient(
                base_url=f"{self.settings.veeam_api_base_url}/",
                transport=self._transport,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
                verify=self.settings.veeam_tls_verify,
                headers={
                    "Accept": "application/json",
                    "x-api-version": self.settings.veeam_api_version,
                },
            ) as client:
                response = await client.post(
                    "api/oauth2/token",
                    data={
                        "grant_type": "password",
                        "username": self.settings.veeam_username,
                        "password": self.settings.veeam_password.get_secret_value(),
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            if 300 <= response.status_code < 400:
                raise VeeamClientError("Veeam authentication redirects are not allowed")
            if response.status_code != 200:
                raise VeeamClientError(
                    f"Veeam authentication failed with status {response.status_code}"
                )
            if len(response.content) > max_response_bytes:
                raise VeeamClientError("Veeam authentication response exceeded the byte limit")
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise VeeamClientError("Veeam authentication returned invalid JSON") from exc
            if not isinstance(payload, Mapping):
                raise VeeamClientError("Veeam authentication response must be a JSON object")
            token = payload.get("access_token")
            if not isinstance(token, str) or not token:
                raise VeeamClientError("Veeam authentication response omitted access_token")
            expires_in = _integer(payload.get("expires_in"), minimum=30) or 300
            self._token = token
            self._token_valid_until = time.monotonic() + max(15, expires_in - 30)
            return token

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        if not path.startswith("api/v1/") or ".." in path or "?" in path:
            raise ValueError("Veeam adapter path must be a fixed relative /api/v1 route")
        token = await self._access_token(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        async with httpx.AsyncClient(
            base_url=f"{self.settings.veeam_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.veeam_tls_verify,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "x-api-version": self.settings.veeam_api_version,
                "User-Agent": "flowoox-mcp-veeam/0.1",
            },
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise VeeamClientError("Veeam redirects are not allowed")
            if response.status_code == 429:
                raw = response.headers.get("Retry-After", "").strip()
                raise VeeamRateLimitError(int(raw) if raw.isdecimal() else None)
            if response.status_code == 401:
                self._token = ""
                self._token_valid_until = 0.0
                raise VeeamClientError(
                    "Veeam bearer token was rejected; automatic replay is disabled"
                )
            if response.status_code != 200:
                raise VeeamClientError(
                    f"Veeam GET operation failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise VeeamClientError("Veeam response exceeded the configured byte limit")
                body.extend(chunk)
        try:
            return json.loads(body), len(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VeeamClientError("Veeam returned invalid JSON") from exc

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("Veeam operation received unsupported parameters")
        return dict(query.parameters)

    def _offset(self, cursor: str | None) -> int:
        if cursor is None:
            return 0
        if not cursor.startswith("offset:"):
            raise ValueError("unsupported Veeam pagination cursor")
        raw = cursor.removeprefix("offset:")
        if not raw.isdecimal() or len(raw) > 6:
            raise ValueError("invalid Veeam offset cursor")
        offset = int(raw)
        if offset > self.settings.veeam_max_offset:
            raise ValueError("Veeam pagination cursor exceeds configured offset limit")
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
        if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
            raise VeeamClientError("Veeam list response must contain a data array")
        pagination = payload.get("pagination")
        if not isinstance(pagination, Mapping):
            raise VeeamClientError("Veeam page omitted pagination metadata")
        data = payload["data"]
        returned_skip = _integer(pagination.get("skip"), minimum=0)
        returned_limit = _integer(pagination.get("limit"), minimum=0)
        count = _integer(pagination.get("count"), minimum=0)
        total = _integer(pagination.get("total"), minimum=0)
        if None in {returned_skip, returned_limit, count, total}:
            raise VeeamClientError("Veeam page has invalid pagination metadata")
        if (
            returned_skip != requested_offset
            or returned_limit > requested_limit
            or len(data) > requested_limit
            or count != len(data)
        ):
            raise VeeamClientError("Veeam returned an unexpected or oversized page")
        rows = []
        for raw in data:
            if not isinstance(raw, Mapping):
                raise VeeamClientError("Veeam page row must be a JSON object")
            rows.append(projector(raw))
        next_offset = requested_offset + len(data)
        next_cursor = None
        if next_offset < total and next_offset <= self.settings.veeam_max_offset:
            next_cursor = f"offset:{next_offset}"
        return ReadOnlyPage(
            items=rows,
            next_cursor=next_cursor,
            truncated=next_offset < total,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.veeam_cache_max_age_seconds),
        )

    async def _list(
        self,
        query: ReadOnlyQuery,
        *,
        path: str,
        projector: Any,
        fixed_params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        offset = self._offset(query.page.cursor)
        params = [("skip", str(offset)), ("limit", str(query.page.limit)), *fixed_params]
        payload, payload_bytes = await self._request_json(
            path,
            params=params,
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

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "veeam.jobs.states":
            self._parameters(query, frozenset())
            return await self._list(
                query,
                path="api/v1/jobs/states",
                projector=_project_job_state,
                fixed_params=(("orderColumn", "LastRun"), ("orderAsc", "false")),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "veeam.sessions.list":
            self._parameters(query, frozenset())
            return await self._list(
                query,
                path="api/v1/sessions",
                projector=_project_session,
                fixed_params=(("orderColumn", "CreationTime"), ("orderAsc", "false")),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "veeam.repositories.states":
            self._parameters(query, frozenset())
            return await self._list(
                query,
                path="api/v1/backupInfrastructure/repositories/states",
                projector=_project_repository,
                fixed_params=(("orderColumn", "Name"), ("orderAsc", "true")),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "veeam.backups.list":
            self._parameters(query, frozenset())
            return await self._list(
                query,
                path="api/v1/backups",
                projector=_project_backup,
                fixed_params=(("orderColumn", "CreationTime"), ("orderAsc", "false")),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "veeam.restore_points.list":
            parameters = self._parameters(query, frozenset({"history_hours"}))
            hours = _integer(parameters.get("history_hours"), minimum=1)
            if hours is None or hours > self.settings.veeam_max_history_hours:
                raise ValueError("history_hours exceeds the configured Veeam history limit")
            cutoff = datetime.now(UTC) - timedelta(hours=hours)
            return await self._list(
                query,
                path="api/v1/restorePoints",
                projector=_project_restore_point,
                fixed_params=(
                    ("orderColumn", "CreationTime"),
                    ("orderAsc", "false"),
                    ("createdAfterFilter", cutoff.isoformat()),
                ),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("Veeam operation is not in the fixed read-only transport allowlist")
