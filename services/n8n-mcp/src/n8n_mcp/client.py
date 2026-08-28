from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import ExecutionObservation, WorkflowObservation, WorkflowTagObservation

_WORKFLOW_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_EXECUTION_ID_RE = re.compile(r"^[0-9]{1,32}$")
_EXECUTION_STATUSES = frozenset(
    {"error", "success", "running", "waiting", "canceled", "crashed", "new"}
)


class N8nClientError(RuntimeError):
    """Raised when the fixed n8n read-only adapter rejects or cannot parse a response."""


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


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


def _workflow_id(value: Any, field_name: str = "workflow_id") -> str:
    text = _text(value, max_length=129).strip()
    if not _WORKFLOW_ID_RE.fullmatch(text):
        raise ValueError(f"{field_name} contains unsupported characters")
    return text


def _execution_id(value: Any) -> str:
    text = _text(value, max_length=33).strip()
    if not _EXECUTION_ID_RE.fullmatch(text):
        raise ValueError("execution_id must be a bounded decimal identifier")
    return text


def _project_tags(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    tags: list[dict[str, Any]] = []
    for item in value[:32]:
        if not isinstance(item, Mapping):
            continue
        tags.append(
            WorkflowTagObservation(
                tag_id=_text(item.get("id"), max_length=128),
                name=_text(item.get("name"), max_length=256),
            ).model_dump(mode="json")
        )
    return tags


def _project_workflow(row: Mapping[str, Any]) -> dict[str, Any]:
    active = _boolean(row.get("active"))
    if active is None:
        raise N8nClientError("n8n workflow response omitted a valid active flag")
    archived = _boolean(row.get("isArchived", row.get("archived")))
    return WorkflowObservation(
        workflow_id=_workflow_id(row.get("id")),
        name=_text(row.get("name"), max_length=512),
        active=active,
        archived=archived,
        created_at=_text(row.get("createdAt"), max_length=128),
        updated_at=_text(row.get("updatedAt"), max_length=128),
        tags=_project_tags(row.get("tags")),
    ).model_dump(mode="json")


def _project_execution(row: Mapping[str, Any]) -> dict[str, Any]:
    workflow = _workflow_id(row.get("workflowId"))
    status = _text(row.get("status"), max_length=64).strip().lower()
    if not status:
        status = "unknown"
    return ExecutionObservation(
        execution_id=_execution_id(row.get("id")),
        workflow_id=workflow,
        status=status,
        mode=_text(row.get("mode"), max_length=64),
        started_at=_text(row.get("startedAt"), max_length=128),
        stopped_at=_text(row.get("stoppedAt"), max_length=128),
        wait_till=_text(row.get("waitTill"), max_length=128),
        retry_of=_text(row.get("retryOf"), max_length=128),
        retry_success_id=_text(row.get("retrySuccessId"), max_length=128),
        finished=_boolean(row.get("finished")),
    ).model_dump(mode="json")


class N8nReadOnlyTransport:
    """n8n Public API adapter with a fixed GET-only observation surface."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.n8n_backend_read_only:
            raise ValueError("N8N_BACKEND_READ_ONLY=true is required for the n8n reader identity")
        if not settings.configured:
            raise ValueError("N8N_API_BASE_URL and N8N_API_KEY are required")
        self.settings = settings
        self._transport = transport

    @property
    def read_only(self) -> bool:
        return self.settings.n8n_backend_read_only

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Mapping[str, Any], int]:
        if path.startswith("/") or ".." in path:
            raise ValueError("n8n adapter path must be a fixed relative API path")
        headers = {
            "Accept": "application/json",
            "X-N8N-API-KEY": self.settings.n8n_api_key.get_secret_value(),
            "User-Agent": "flowoox-mcp-n8n/0.1",
        }
        async with httpx.AsyncClient(
            base_url=f"{self.settings.n8n_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.n8n_tls_verify,
            headers=headers,
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise N8nClientError("n8n redirects are not allowed")
            if response.status_code != 200:
                raise N8nClientError(
                    f"n8n GET operation failed with status {response.status_code}"
                )
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise N8nClientError("n8n response exceeded the configured byte limit")
                body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise N8nClientError("n8n returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise N8nClientError("n8n response must be a JSON object")
        return payload, len(body)

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("n8n operation received unsupported parameters")
        return dict(query.parameters)

    @staticmethod
    def _next_cursor(payload: Mapping[str, Any]) -> str | None:
        value = payload.get("nextCursor")
        if value is None or value == "":
            return None
        cursor = str(value)
        if len(cursor) > 1024 or any(character.isspace() for character in cursor):
            raise N8nClientError("n8n returned an invalid pagination cursor")
        return cursor

    def _require_allowed_workflow(self, workflow_id: Any) -> str:
        normalized = _workflow_id(workflow_id)
        allowlist = self.settings.allowed_workflow_ids
        if allowlist and normalized not in allowlist:
            raise PermissionError("workflow is outside the deployment read-only allowlist")
        return normalized

    def _execution_scope(self, parameters: Mapping[str, Any]) -> str | None:
        raw = parameters.get("workflow_id")
        workflow_id = self._require_allowed_workflow(raw) if raw is not None and raw != "" else None
        if self.settings.allowed_workflow_ids and workflow_id is None:
            raise PermissionError(
                "workflow_id is required for execution listing when a workflow allowlist is configured"
            )
        return workflow_id

    async def _workflows(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"active"}))
        params: list[tuple[str, str]] = [("limit", str(query.page.limit))]
        if query.page.cursor:
            params.append(("cursor", query.page.cursor))
        if "active" in parameters:
            active = parameters["active"]
            if not isinstance(active, bool):
                raise ValueError("active must be a boolean")
            params.append(("active", "true" if active else "false"))

        payload, payload_bytes = await self._request_json(
            "workflows",
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_rows = payload.get("data", [])
        if not isinstance(raw_rows, list):
            raise N8nClientError("n8n workflows response must contain a data list")
        if len(raw_rows) > query.page.limit:
            raise N8nClientError("n8n workflows response returned more rows than requested")
        rows: list[dict[str, Any]] = []
        allowlist = self.settings.allowed_workflow_ids
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise N8nClientError("n8n workflow row must be a JSON object")
            projected = _project_workflow(raw_row)
            if allowlist and projected["workflow_id"] not in allowlist:
                continue
            rows.append(projected)
        cursor = self._next_cursor(payload)
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None or len(rows) < len(raw_rows),
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.n8n_cache_max_age_seconds),
        )

    async def _executions(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"workflow_id", "status"}))
        workflow_id = self._execution_scope(parameters)
        status = parameters.get("status")
        if (
            status is not None
            and status != ""
            and (not isinstance(status, str) or status not in _EXECUTION_STATUSES)
        ):
            raise ValueError("execution status is not in the fixed safe allowlist")

        params: list[tuple[str, str]] = [
            ("limit", str(query.page.limit)),
            ("includeData", "false"),
        ]
        if query.page.cursor:
            params.append(("cursor", query.page.cursor))
        if workflow_id is not None:
            params.append(("workflowId", workflow_id))
        if status:
            params.append(("status", status))

        payload, payload_bytes = await self._request_json(
            "executions",
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_rows = payload.get("data", [])
        if not isinstance(raw_rows, list):
            raise N8nClientError("n8n executions response must contain a data list")
        if len(raw_rows) > query.page.limit:
            raise N8nClientError("n8n executions response returned more rows than requested")
        rows: list[dict[str, Any]] = []
        allowlist = self.settings.allowed_workflow_ids
        for raw_row in raw_rows:
            if not isinstance(raw_row, Mapping):
                raise N8nClientError("n8n execution row must be a JSON object")
            projected = _project_execution(raw_row)
            if workflow_id is not None and projected["workflow_id"] != workflow_id:
                raise N8nClientError("n8n returned an execution outside the requested workflow")
            if allowlist and projected["workflow_id"] not in allowlist:
                raise N8nClientError("n8n returned an execution outside the deployment allowlist")
            rows.append(projected)
        cursor = self._next_cursor(payload)
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.n8n_cache_max_age_seconds),
        )

    async def _execution(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"execution_id", "workflow_id"}))
        execution_id = _execution_id(parameters.get("execution_id"))
        expected_workflow = parameters.get("workflow_id")
        expected = (
            self._require_allowed_workflow(expected_workflow)
            if expected_workflow is not None and expected_workflow != ""
            else None
        )
        if self.settings.allowed_workflow_ids and expected is None:
            raise PermissionError(
                "workflow_id is required for exact execution observation when a workflow allowlist is configured"
            )
        payload, payload_bytes = await self._request_json(
            f"executions/{execution_id}",
            params=(("includeData", "false"),),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        raw_row: Any = payload.get("data", payload)
        if not isinstance(raw_row, Mapping):
            raise N8nClientError("n8n execution response must be a JSON object")
        projected = _project_execution(raw_row)
        if expected is not None and projected["workflow_id"] != expected:
            raise N8nClientError("n8n returned an execution outside the expected workflow")
        allowlist = self.settings.allowed_workflow_ids
        if allowlist and projected["workflow_id"] not in allowlist:
            raise N8nClientError("n8n returned an execution outside the deployment allowlist")
        return ReadOnlyPage(
            items=[projected],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.n8n_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "n8n.workflows.list":
            return await self._workflows(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "n8n.executions.list":
            return await self._executions(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "n8n.executions.get":
            return await self._execution(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("n8n operation is not implemented by the fixed read-only adapter")
