from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import (
    ReadOnlyConnectorPolicy,
    redacted_connector_metadata,
)

CONTRACT = "flowoox.docker-diagnostics"
CONTRACT_VERSION = "1.3.0"

TOOL_POLICIES = (
    ToolPolicy(name="docker.health.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.containers.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.containers.logs", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.containers.stats", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.images.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.volumes.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.networks.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.resources.inventory", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.events.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.diagnostics.bundle", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="docker.diagnostics.detail", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)

_DESCRIPTIONS = {
    "docker.health.observe": "Return bounded daemon reachability, host resource and engine health metadata.",
    "docker.containers.list": "Return a bounded normalized container page without environment, labels, commands or host mount sources.",
    "docker.containers.logs": "Return a bounded finite historical container log tail with timestamps and best-effort secret redaction; never follow a live stream.",
    "docker.containers.stats": "Return one bounded non-streaming resource-stat sample for an exact validated container target.",
    "docker.images.list": "Return bounded image identity, repository references, creation time and size without image labels or configuration.",
    "docker.volumes.list": "Return bounded volume identity, driver, scope and usage metadata without mountpoints, labels or driver options.",
    "docker.networks.list": "Return bounded network identity and aggregate attachment/IPAM counts without endpoint addresses, labels or options.",
    "docker.resources.inventory": "Aggregate bounded image, volume and network inventory under one shared query budget before detail fan-out.",
    "docker.events.list": "Return a bounded finite Docker event window with an explicit object-type allowlist and minimized actor attributes.",
    "docker.diagnostics.bundle": "Aggregate daemon health and sampled container/network/storage relationships under one shared query budget.",
    "docker.diagnostics.detail": "Select anomalous containers from one bounded aggregate inventory, then fetch one-shot stats only for the selected candidates under the same query budget.",
}


def capabilities(
    connector_policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    direct_socket_override_enabled: bool,
    max_log_window_seconds: int,
    max_event_window_seconds: int,
    max_detail_candidates: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "connector": redacted_connector_metadata(
                connector_policy,
                backend_kind="docker-engine-api",
                extra={"direct_socket_override_enabled": direct_socket_override_enabled},
            ),
            "query_budget": budget_limits.model_dump(mode="json"),
            "diagnostic_windows": {
                "max_log_window_seconds": max_log_window_seconds,
                "max_event_window_seconds": max_event_window_seconds,
                "live_log_follow": False,
                "live_event_stream": False,
                "live_stats_stream": False,
                "container_stats_one_shot": True,
            },
            "diagnostic_detail": {
                "aggregate_candidate_selection_required": True,
                "max_candidates": max_detail_candidates,
                "automatic_log_fetch": False,
                "automatic_event_fetch": False,
                "per_candidate_stats_samples": 1,
            },
            "resource_minimization": {
                "image_labels_or_config": False,
                "volume_mountpoints_labels_or_options": False,
                "network_endpoint_addresses_labels_or_options": False,
                "raw_cgroup_stats": False,
            },
            "writes_enabled": False,
            "arbitrary_api_path": False,
            "arbitrary_http_method": False,
            "arbitrary_command_or_exec": False,
            "raw_inspect_payloads": False,
        },
        "capabilities": [
            {
                "id": policy.name,
                "phase": policy.phase.value,
                "risk": policy.risk.value,
                "requires_approval": policy.requires_approval,
                "description": _DESCRIPTIONS[policy.name],
            }
            for policy in TOOL_POLICIES
        ],
    }
