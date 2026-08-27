from __future__ import annotations

import asyncio
import re
from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    BackendEnvelope,
    ClusterEventObservation,
    ClusterGroupDetailObservation,
    ClusterGroupObservation,
    ClusterNetworkObservation,
    ClusterNodeObservation,
    ClusterObservation,
    ClusterQuorumObservation,
    ClusterResourceObservation,
    ClusterStorageObservation,
)
from .runner import PowerShellRunner
from .scripts import ScriptId

_OPERATION_SCRIPTS: dict[str, ScriptId] = {
    "failovercluster.cluster.observe": ScriptId.CLUSTER,
    "failovercluster.node.list": ScriptId.NODES,
    "failovercluster.group.list": ScriptId.GROUPS,
    "failovercluster.group.observe": ScriptId.GROUP_DETAIL,
    "failovercluster.resource.list": ScriptId.RESOURCES,
    "failovercluster.network.list": ScriptId.NETWORKS,
    "failovercluster.storage.list": ScriptId.STORAGE,
    "failovercluster.quorum.observe": ScriptId.QUORUM,
    "failovercluster.event.list": ScriptId.EVENTS,
}

_MODELS: dict[str, type] = {
    "failovercluster.cluster.observe": ClusterObservation,
    "failovercluster.node.list": ClusterNodeObservation,
    "failovercluster.group.list": ClusterGroupObservation,
    "failovercluster.group.observe": ClusterGroupDetailObservation,
    "failovercluster.resource.list": ClusterResourceObservation,
    "failovercluster.network.list": ClusterNetworkObservation,
    "failovercluster.storage.list": ClusterStorageObservation,
    "failovercluster.quorum.observe": ClusterQuorumObservation,
    "failovercluster.event.list": ClusterEventObservation,
}

_PAGEABLE = frozenset(
    {
        "failovercluster.node.list",
        "failovercluster.group.list",
        "failovercluster.resource.list",
        "failovercluster.network.list",
        "failovercluster.storage.list",
    }
)
_NAME_RE = re.compile(r"^[^\x00-\x1f*?\[\]]{1,256}$")


def _exact_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _exact_name(value: Any, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError("group_name must be a string")
    value = value.strip()
    if not value and not required:
        return ""
    if not _NAME_RE.fullmatch(value):
        raise ValueError("group_name contains unsupported wildcard/control characters")
    return value


class FailoverClusterReadOnlyTransport:
    """Fixed PowerShell/WinRM adapter with configured targets and no generic command surface."""

    def __init__(self, settings: Settings, *, runner: PowerShellRunner | None = None) -> None:
        if not settings.failovercluster_backend_read_only:
            raise ValueError("FAILOVERCLUSTER_BACKEND_READ_ONLY=true is required")
        self.settings = settings
        self.targets = settings.targets
        self.runner = runner or PowerShellRunner(settings.failovercluster_powershell_executable)

    @property
    def read_only(self) -> bool:
        return self.settings.failovercluster_backend_read_only

    def _offset(self, query: ReadOnlyQuery) -> int:
        if query.page.cursor is None:
            return 0
        if query.operation not in _PAGEABLE:
            raise ValueError("this Failover Cluster operation does not support pagination cursors")
        if not query.page.cursor.isdecimal():
            raise ValueError("Failover Cluster pagination cursor must be a decimal offset")
        offset = int(query.page.cursor)
        if offset > 10_000:
            raise ValueError("Failover Cluster pagination cursor exceeds the fixed offset cap")
        return offset

    def _payload(self, query: ReadOnlyQuery) -> tuple[str, dict[str, Any]]:
        parameters = dict(query.parameters)
        target_id = parameters.pop("target_id", None)
        if not isinstance(target_id, str) or target_id not in self.targets:
            raise PermissionError("Failover Cluster target is not in the configured logical target allowlist")

        offset = self._offset(query)
        payload: dict[str, Any] = {"limit": query.page.limit, "offset": offset}

        if query.operation in {"failovercluster.cluster.observe", "failovercluster.quorum.observe"}:
            if query.page.cursor is not None or parameters:
                raise ValueError("cluster/quorum observation does not accept cursor or extra parameters")
        elif query.operation in {
            "failovercluster.node.list",
            "failovercluster.group.list",
            "failovercluster.network.list",
            "failovercluster.storage.list",
        }:
            if parameters:
                raise ValueError("inventory operation received unsupported parameters")
        elif query.operation == "failovercluster.group.observe":
            if query.page.cursor is not None:
                raise ValueError("group observation does not support cursors")
            payload["groupName"] = _exact_name(parameters.pop("group_name", None))
            payload["resourceLimit"] = _bounded_int(
                parameters.pop("resource_limit", self.settings.failovercluster_max_group_resources),
                "resource_limit",
                1,
                self.settings.failovercluster_max_group_resources,
            )
        elif query.operation == "failovercluster.resource.list":
            payload["groupName"] = _exact_name(parameters.pop("group_name", None), required=False)
        elif query.operation == "failovercluster.event.list":
            if query.page.cursor is not None:
                raise ValueError("Failover Cluster event queries do not support cursors")
            level = parameters.pop("level", "error")
            if level not in {"all", "critical", "error", "warning"}:
                raise ValueError("level must be all, critical, error, or warning")
            payload.update(
                {
                    "lookbackMinutes": _bounded_int(
                        parameters.pop("lookback_minutes", 60),
                        "lookback_minutes",
                        1,
                        self.settings.failovercluster_max_event_lookback_minutes,
                    ),
                    "level": level,
                    "includeMessage": _exact_bool(
                        parameters.pop("include_message", False), "include_message"
                    ),
                }
            )
        else:
            raise PermissionError("Failover Cluster operation is not implemented by the fixed adapter")

        if parameters:
            raise ValueError("Failover Cluster operation received unsupported parameters")
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
            raise PermissionError(
                "Failover Cluster operation is not implemented by the fixed adapter"
            ) from exc
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
            raise ValueError("Failover Cluster backend returned more items than requested")
        return ReadOnlyPage(
            items=items,
            next_cursor=envelope.nextCursor,
            truncated=envelope.nextCursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.failovercluster_cache_max_age_seconds),
        )
