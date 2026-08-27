from __future__ import annotations

import asyncio
import re
from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    BackendEnvelope,
    CheckpointObservation,
    HyperVEventObservation,
    HyperVHostObservation,
    ReplicationObservation,
    VHDObservation,
    VMDetailObservation,
    VMObservation,
    VMSwitchObservation,
)
from .runner import PowerShellRunner
from .scripts import ScriptId

_OPERATION_SCRIPTS: dict[str, ScriptId] = {
    "hyperv.host.observe": ScriptId.HOST,
    "hyperv.vm.list": ScriptId.VMS,
    "hyperv.vm.observe": ScriptId.VM_DETAIL,
    "hyperv.switch.list": ScriptId.SWITCHES,
    "hyperv.checkpoint.list": ScriptId.CHECKPOINTS,
    "hyperv.vhd.list": ScriptId.VHDS,
    "hyperv.replication.list": ScriptId.REPLICATION,
    "hyperv.event.list": ScriptId.EVENTS,
}

_MODELS: dict[str, type] = {
    "hyperv.host.observe": HyperVHostObservation,
    "hyperv.vm.list": VMObservation,
    "hyperv.vm.observe": VMDetailObservation,
    "hyperv.switch.list": VMSwitchObservation,
    "hyperv.checkpoint.list": CheckpointObservation,
    "hyperv.vhd.list": VHDObservation,
    "hyperv.replication.list": ReplicationObservation,
    "hyperv.event.list": HyperVEventObservation,
}

_PAGEABLE = frozenset(
    {
        "hyperv.vm.list",
        "hyperv.switch.list",
        "hyperv.checkpoint.list",
        "hyperv.vhd.list",
        "hyperv.replication.list",
    }
)
_VM_NAME_RE = re.compile(r"^[^\x00-\x1f*?\[\]]{1,256}$")


def _exact_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _vm_name(value: Any, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError("vm_name must be a string")
    value = value.strip()
    if not value and not required:
        return ""
    if not _VM_NAME_RE.fullmatch(value):
        raise ValueError("vm_name contains unsupported wildcard/control characters")
    return value


class HyperVReadOnlyTransport:
    """Fixed PowerShell/WinRM adapter with configured targets and no generic command surface."""

    def __init__(self, settings: Settings, *, runner: PowerShellRunner | None = None) -> None:
        if not settings.hyperv_backend_read_only:
            raise ValueError("HYPERV_BACKEND_READ_ONLY=true is required")
        self.settings = settings
        self.targets = settings.targets
        self.runner = runner or PowerShellRunner(settings.hyperv_powershell_executable)

    @property
    def read_only(self) -> bool:
        return self.settings.hyperv_backend_read_only

    def _offset(self, query: ReadOnlyQuery) -> int:
        if query.page.cursor is None:
            return 0
        if query.operation not in _PAGEABLE:
            raise ValueError("this Hyper-V operation does not support pagination cursors")
        if not query.page.cursor.isdecimal():
            raise ValueError("Hyper-V pagination cursor must be a decimal offset")
        offset = int(query.page.cursor)
        if offset > 10_000:
            raise ValueError("Hyper-V pagination cursor exceeds the fixed offset cap")
        return offset

    def _payload(self, query: ReadOnlyQuery) -> tuple[str, dict[str, Any]]:
        parameters = dict(query.parameters)
        target_id = parameters.pop("target_id", None)
        if not isinstance(target_id, str) or target_id not in self.targets:
            raise PermissionError("Hyper-V target is not in the configured logical target allowlist")

        offset = self._offset(query)
        payload: dict[str, Any] = {"limit": query.page.limit, "offset": offset}

        if query.operation == "hyperv.host.observe":
            if query.page.cursor is not None or parameters:
                raise ValueError("host observation does not accept cursor or extra parameters")
        elif query.operation in {"hyperv.vm.list", "hyperv.switch.list"}:
            if parameters:
                raise ValueError("inventory operation received unsupported parameters")
        elif query.operation == "hyperv.vm.observe":
            if query.page.cursor is not None:
                raise ValueError("VM observation does not support cursors")
            payload["vmName"] = _vm_name(parameters.pop("vm_name", None))
        elif query.operation in {"hyperv.checkpoint.list", "hyperv.vhd.list"}:
            payload["vmName"] = _vm_name(parameters.pop("vm_name", None))
            if query.operation == "hyperv.vhd.list" and query.page.limit > self.settings.hyperv_max_vhd_page_size:
                raise ValueError(
                    f"VHD page size exceeds operation maximum of {self.settings.hyperv_max_vhd_page_size}"
                )
        elif query.operation == "hyperv.replication.list":
            payload["vmName"] = _vm_name(parameters.pop("vm_name", None), required=False)
        elif query.operation == "hyperv.event.list":
            if query.page.cursor is not None:
                raise ValueError("Hyper-V event queries do not support cursors")
            log_id = parameters.pop("log_id", "vmms")
            if log_id not in {"vmms", "worker"}:
                raise ValueError("log_id must be vmms or worker")
            level = parameters.pop("level", "error")
            if level not in {"all", "critical", "error", "warning"}:
                raise ValueError("level must be all, critical, error, or warning")
            payload.update(
                {
                    "logId": log_id,
                    "lookbackMinutes": _bounded_int(
                        parameters.pop("lookback_minutes", 60),
                        "lookback_minutes",
                        1,
                        self.settings.hyperv_max_event_lookback_minutes,
                    ),
                    "level": level,
                    "includeMessage": _exact_bool(
                        parameters.pop("include_message", False), "include_message"
                    ),
                }
            )
        else:
            raise PermissionError("Hyper-V operation is not implemented by the fixed adapter")

        if parameters:
            raise ValueError("Hyper-V operation received unsupported parameters")
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
            raise PermissionError("Hyper-V operation is not implemented by the fixed adapter") from exc
        target_id, payload = self._payload(query)
        raw, payload_bytes = await asyncio.to_thread(
            self.runner.run,
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
            raise ValueError("Hyper-V backend returned more items than requested")
        return ReadOnlyPage(
            items=items,
            next_cursor=envelope.nextCursor,
            truncated=envelope.nextCursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.hyperv_cache_max_age_seconds),
        )
