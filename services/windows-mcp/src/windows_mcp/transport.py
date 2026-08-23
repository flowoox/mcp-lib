from __future__ import annotations

from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    BackendEnvelope,
    CertificateObservation,
    EventObservation,
    FeatureObservation,
    HostObservation,
    HyperVHostObservation,
    ProcessObservation,
    ServiceObservation,
    UpdateObservation,
)
from .runner import PowerShellRunner
from .scripts import ScriptId

_OPERATION_SCRIPTS: dict[str, ScriptId] = {
    "windows.host.inventory": ScriptId.HOST,
    "windows.service.inventory": ScriptId.SERVICES,
    "windows.process.inventory": ScriptId.PROCESSES,
    "windows.feature.inventory": ScriptId.FEATURES,
    "windows.event.inventory": ScriptId.EVENTS,
    "windows.certificate.inventory": ScriptId.CERTIFICATES,
    "windows.update.inventory": ScriptId.UPDATES,
    "windows.hyperv.host.inventory": ScriptId.HYPERV_HOST,
}

_MODELS: dict[str, type] = {
    "windows.host.inventory": HostObservation,
    "windows.service.inventory": ServiceObservation,
    "windows.process.inventory": ProcessObservation,
    "windows.feature.inventory": FeatureObservation,
    "windows.event.inventory": EventObservation,
    "windows.certificate.inventory": CertificateObservation,
    "windows.update.inventory": UpdateObservation,
    "windows.hyperv.host.inventory": HyperVHostObservation,
}

_PAGEABLE = frozenset(
    {
        "windows.service.inventory",
        "windows.process.inventory",
        "windows.feature.inventory",
        "windows.certificate.inventory",
        "windows.update.inventory",
    }
)


def _exact_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class WindowsReadOnlyTransport:
    """Fixed PowerShell/WinRM adapter with configured targets and no arbitrary command surface."""

    def __init__(self, settings: Settings, *, runner: PowerShellRunner | None = None) -> None:
        if not settings.windows_backend_read_only:
            raise ValueError("WINDOWS_BACKEND_READ_ONLY=true is required")
        self.settings = settings
        self.targets = settings.targets
        self.allowed_event_logs = settings.allowed_event_logs
        self.runner = runner or PowerShellRunner(settings.windows_powershell_executable)

    @property
    def read_only(self) -> bool:
        return self.settings.windows_backend_read_only

    def _offset(self, query: ReadOnlyQuery) -> int:
        if query.page.cursor is None:
            return 0
        if query.operation not in _PAGEABLE:
            raise ValueError("this Windows operation does not support pagination cursors")
        if not query.page.cursor.isdecimal():
            raise ValueError("Windows pagination cursor must be a decimal offset")
        offset = int(query.page.cursor)
        if offset > 10_000:
            raise ValueError("Windows pagination cursor exceeds the fixed offset cap")
        return offset

    def _payload(self, query: ReadOnlyQuery) -> tuple[str, dict[str, Any]]:
        parameters = dict(query.parameters)
        target_id = parameters.pop("target_id", None)
        if not isinstance(target_id, str) or target_id not in self.targets:
            raise PermissionError("Windows target is not in the configured logical target allowlist")
        offset = self._offset(query)
        payload: dict[str, Any] = {"limit": query.page.limit, "offset": offset}

        if query.operation == "windows.host.inventory" or query.operation == "windows.hyperv.host.inventory":
            if parameters:
                raise ValueError("host observation does not accept additional parameters")
        elif query.operation == "windows.service.inventory":
            state = parameters.pop("state", "all")
            if state not in {"all", "running", "stopped"}:
                raise ValueError("state must be all, running, or stopped")
            payload["state"] = state
        elif query.operation == "windows.process.inventory":
            sort_by = parameters.pop("sort_by", "working_set")
            if sort_by not in {"working_set", "cpu", "name"}:
                raise ValueError("sort_by must be working_set, cpu, or name")
            payload["sortBy"] = sort_by
        elif query.operation == "windows.feature.inventory":
            payload["installedOnly"] = _exact_bool(parameters.pop("installed_only", True), "installed_only")
        elif query.operation == "windows.event.inventory":
            if query.page.cursor is not None:
                raise ValueError("Windows event queries do not support cursors")
            log_name = parameters.pop("log_name", None)
            if not isinstance(log_name, str) or log_name not in self.allowed_event_logs:
                raise PermissionError("event log is not in WINDOWS_ALLOWED_EVENT_LOGS")
            level = parameters.pop("level", "error")
            if level not in {"all", "critical", "error", "warning"}:
                raise ValueError("level must be all, critical, error, or warning")
            payload.update(
                {
                    "logName": log_name,
                    "lookbackMinutes": _bounded_int(
                        parameters.pop("lookback_minutes", 60), "lookback_minutes", 1, 10_080
                    ),
                    "level": level,
                    "includeMessage": _exact_bool(
                        parameters.pop("include_message", False), "include_message"
                    ),
                }
            )
        elif query.operation == "windows.certificate.inventory":
            store_id = parameters.pop("store_id", "machine-my")
            if store_id not in {"machine-my", "machine-root", "machine-ca"}:
                raise ValueError("unsupported fixed certificate store ID")
            within = parameters.pop("expiring_within_days", None)
            if within is not None:
                within = _bounded_int(within, "expiring_within_days", 0, 3_650)
            payload.update({"storeId": store_id, "expiringWithinDays": within})
        elif query.operation == "windows.update.inventory":
            pass
        else:
            raise PermissionError("Windows operation is not implemented by the fixed adapter")

        if parameters:
            raise ValueError("Windows operation received unsupported parameters")
        return target_id, payload

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        try:
            script_id = _OPERATION_SCRIPTS[query.operation]
        except KeyError as exc:
            raise PermissionError("Windows operation is not implemented by the fixed adapter") from exc
        target_id, payload = self._payload(query)
        raw, payload_bytes = self.runner.run(
            script_id,
            self.targets[target_id],
            payload,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        envelope = BackendEnvelope.model_validate(raw)
        model = _MODELS[query.operation]
        items = [model.model_validate(item).model_dump(mode="json") for item in envelope.items]
        if len(items) > query.page.limit:
            raise ValueError("Windows backend returned more items than requested")
        return ReadOnlyPage(
            items=items,
            next_cursor=envelope.nextCursor,
            truncated=envelope.nextCursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.windows_cache_max_age_seconds),
        )
