from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy

CONTRACT = "flowoox.active-directory"
CONTRACT_VERSION = "1.3.0"

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
    ToolPolicy(name="ad.user.groups", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.computer.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.group.get", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="ad.ou.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="ad.user.enabled.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.enabled.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.enabled.verify", phase=OperationPhase.VERIFY, risk=RiskLevel.READ_ONLY
    ),
    ToolPolicy(
        name="ad.user.group-membership.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.group-membership.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.group-membership.verify",
        phase=OperationPhase.VERIFY,
        risk=RiskLevel.READ_ONLY,
    ),
    ToolPolicy(
        name="ad.user.provision-disabled.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.provision-disabled.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="ad.user.provision-disabled.verify",
        phase=OperationPhase.VERIFY,
        risk=RiskLevel.READ_ONLY,
    ),
)

_DESCRIPTIONS = {
    "ad.domain.summary": "Return forest, domain, FSMO and domain-controller inventory.",
    "ad.replication.health": "Return replication failures and partner metadata.",
    "ad.dns.discovery": "Resolve the domain's core LDAP and Kerberos SRV discovery records.",
    "ad.secure-channel.local": "Test the local member computer secure channel without repairing it.",
    "ad.security.baseline": "Evaluate a read-only domain security snapshot against a selected baseline.",
    "ad.user.get": "Return a bounded set of non-secret properties for one AD user.",
    "ad.user.groups": "Return direct group memberships for one AD user.",
    "ad.computer.get": "Return a bounded set of properties for one AD computer.",
    "ad.group.get": "Return a bounded set of properties for one AD group.",
    "ad.ou.list": "Return a bounded inventory of organizational units.",
    "ad.user.enabled.plan": "Capture pre-state and plan one user enable/disable mutation.",
    "ad.user.enabled.change": "Enable or disable one user with a signed out-of-band approval grant.",
    "ad.user.enabled.verify": "Independently verify one user's enabled state.",
    "ad.user.group-membership.plan": "Capture pre-state and plan one direct group membership change.",
    "ad.user.group-membership.change": "Add or remove one direct group membership with signed approval.",
    "ad.user.group-membership.verify": "Independently verify one direct group membership state.",
    "ad.user.provision-disabled.plan": "Preflight and plan creation of one disabled AD user.",
    "ad.user.provision-disabled.change": "Ensure one approved disabled AD user exists with exact attributes.",
    "ad.user.provision-disabled.verify": "Independently verify the disabled user and approved attribute set.",
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
            "approval_model": (
                "short-lived HMAC-signed grant bound to operation, target, idempotency key and exact desired-state intent"
            ),
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
