from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT = "flowoox.failovercluster-diagnostics"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="failovercluster.cluster.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.node.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.group.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.group.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.resource.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.network.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.storage.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.quorum.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.event.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="failovercluster.cluster.diagnose", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)


def capabilities(
    budget_limits: QueryBudgetLimits,
    connector_policy: ReadOnlyConnectorPolicy,
    *,
    require_jea: bool,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "connector": redacted_connector_metadata(
                connector_policy,
                backend_kind="powershell-winrm-jea",
                extra={
                    "require_jea": require_jea,
                    "backend_read_only_attestation_required": True,
                },
            ),
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_powershell": False,
            "arbitrary_wmi_or_cim": False,
            "cluster_state_mutation": False,
            "resource_or_group_move": False,
            "quorum_mutation": False,
            "configured_target_alias_required": True,
            "aggregate_before_relationship_fan_out": True,
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
