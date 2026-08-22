from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy

CONTRACT = "flowoox.active-directory"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="ad.domain.summary", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="ad.replication.health", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(
        name="ad.secure-channel.local", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(
        name="ad.security.baseline", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(name="ad.user.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.computer.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.group.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)

_DESCRIPTIONS = {
    "ad.domain.summary": "Return forest, domain, FSMO and domain-controller inventory.",
    "ad.replication.health": "Return replication failures and partner metadata.",
    "ad.secure-channel.local": "Test the local member computer secure channel without repairing it.",
    "ad.security.baseline": "Evaluate a read-only domain security snapshot against a selected baseline.",
    "ad.user.get": "Return a bounded set of non-secret properties for one AD user.",
    "ad.computer.get": "Return a bounded set of properties for one AD computer.",
    "ad.group.get": "Return a bounded set of properties for one AD group.",
}


def capabilities() -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "platform": "windows",
            "requirements": ["PowerShell", "ActiveDirectory RSAT module"],
            "credential_model": "inherited service identity; credentials are not accepted by MCP tools",
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
