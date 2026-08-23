from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

from .endpoints import ENDPOINTS

CONTRACT = "flowoox.entra-diagnostics"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="entra.tenant.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.users.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.groups.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.devices.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.applications.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.service-principals.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.directory-roles.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.conditional-access.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="entra.diagnostics.bundle", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)


def capabilities(
    connector_policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    cloud: str,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "connector": redacted_connector_metadata(connector_policy, backend_kind="microsoft-graph"),
            "cloud": cloud,
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_graph_path": False,
            "arbitrary_odata": False,
            "delegated_user_context": False,
            "raw_graph_payloads": False,
        },
        "requiredApplicationPermissions": sorted(
            {spec.application_permission for spec in ENDPOINTS.values()}
        ),
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
