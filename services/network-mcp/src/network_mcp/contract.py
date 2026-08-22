from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy

CONTRACT = "flowoox.network-diagnostics"
CONTRACT_VERSION = "1.1.0"

TOOL_POLICIES = (
    ToolPolicy(name="network.dns.resolve", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="network.tcp.reachability", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="network.route.selection", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="network.path.trace", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="network.subnet.validate", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="network.diagnostic.bundle", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)

_DESCRIPTIONS = {
    "network.dns.resolve": "Resolve one bare hostname or IP and authorize every resulting address against runtime CIDRs.",
    "network.tcp.reachability": "Probe one TCP port on an authorized target using bounded timeouts.",
    "network.route.selection": "Return the local kernel source-address selection for an authorized target without shell execution.",
    "network.path.trace": "Run a separately gated bounded traceroute against one already-authorized numeric destination using fixed argv and no shell.",
    "network.subnet.validate": "Validate IPv4/IPv6 membership and address properties without network I/O.",
    "network.diagnostic.bundle": "Return bounded DNS, route-selection and TCP evidence for one authorized target.",
}


def capabilities(
    *,
    allowed_cidrs: str,
    max_ports_per_bundle: int,
    path_trace_enabled: bool = False,
    path_trace_max_hops: int = 20,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "target_policy": "all resolved addresses must be inside NETWORK_ALLOWED_CIDRS before active probing",
            "allowed_cidrs": [item.strip() for item in allowed_cidrs.split(",") if item.strip()],
            "max_ports_per_bundle": max_ports_per_bundle,
            "path_trace_enabled": path_trace_enabled,
            "path_trace_max_hops": path_trace_max_hops,
            "path_trace_mode": "fixed-platform-traceroute numeric destination; no caller flags or shell",
            "arbitrary_shell": False,
            "arbitrary_url_fetch": False,
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
