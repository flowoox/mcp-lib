from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits

CONTRACT = "flowoox.fileshare-diagnostics"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="fileshare.roots.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.path.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.directory.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.acl.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.access.explain", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)


def capabilities(budget_limits: QueryBudgetLimits, *, allow_reparse_points: bool) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "backend": "windows-powershell-readonly",
            "backend_read_only_attestation_required": True,
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_command": False,
            "arbitrary_path": False,
            "configured_root_alias_required": True,
            "recursive_directory_walk": False,
            "file_content_read": False,
            "reparse_points_allowed": allow_reparse_points,
            "effective_access_authoritative": False,
        },
        "capabilities": [
            {
                "id": policy.name,
                "phase": policy.phase.value,
                "risk": policy.risk.value,
                "requires_approval": policy.requires_approval,
            }
            for policy in TOOL_POLICIES
        ],
    }
