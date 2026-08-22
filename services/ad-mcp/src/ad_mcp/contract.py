from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy

CONTRACT = "flowoox.active-directory"
CONTRACT_VERSION = "1.2.0"

_WRITE_POLICY_NAMES = frozenset(
    {
        "ad.user.create-disabled.plan",
        "ad.user.create-disabled.change",
        "ad.group.member.add.plan",
        "ad.group.member.add.change",
    }
)

TOOL_POLICIES = (
    ToolPolicy(name="ad.domain.summary", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="ad.replication.health", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(name="ad.dns.discovery", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="ad.secure-channel.local", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(
        name="ad.security.baseline", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(name="ad.user.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.computer.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.group.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.ou.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="ad.user.create-disabled.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.READ_ONLY,
    ),
    ToolPolicy(
        name="ad.user.create-disabled.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.group.member.add.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.READ_ONLY,
    ),
    ToolPolicy(
        name="ad.group.member.add.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
)

_DESCRIPTIONS = {
    "ad.domain.summary": "Return forest, domain, FSMO and domain-controller inventory.",
    "ad.replication.health": "Return replication failures and partner metadata.",
    "ad.dns.discovery": "Resolve the domain's core LDAP and Kerberos SRV discovery records.",
    "ad.secure-channel.local": "Test the local member computer secure channel without repairing it.",
    "ad.security.baseline": "Evaluate a read-only domain security snapshot against a selected baseline.",
    "ad.user.get": "Return a bounded set of non-secret properties for one AD user.",
    "ad.computer.get": "Return a bounded set of properties for one AD computer.",
    "ad.group.get": "Return a bounded set of properties for one AD group.",
    "ad.ou.list": "Return a bounded inventory of organizational units.",
    "ad.user.create-disabled.plan": (
        "Capture pre-state and build an approval challenge for a disabled-user creation."
    ),
    "ad.user.create-disabled.change": (
        "Execute an approved disabled-user creation, verify it, and roll back on failed verification."
    ),
    "ad.group.member.add.plan": (
        "Capture user/group pre-state and build an approval challenge for direct membership."
    ),
    "ad.group.member.add.change": (
        "Execute an approved direct group membership, verify it, and roll back on failure."
    ),
}


def capabilities(*, writes_enabled: bool = False) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "platform": "windows",
            "requirements": ["PowerShell", "ActiveDirectory RSAT module"],
            "credential_model": "inherited service identity; credentials are not accepted by MCP tools",
            "writes_enabled": writes_enabled,
            "write_approval_scheme": "hmac-sha256" if writes_enabled else None,
        },
        "capabilities": [
            {
                "id": policy.name,
                "phase": policy.phase.value,
                "risk": policy.risk.value,
                "requires_approval": policy.requires_approval,
                "available": policy.name not in _WRITE_POLICY_NAMES or writes_enabled,
                "description": _DESCRIPTIONS[policy.name],
            }
            for policy in TOOL_POLICIES
        ],
    }
