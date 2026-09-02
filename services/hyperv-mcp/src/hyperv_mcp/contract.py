from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT = "flowoox.hyperv-diagnostics"
CONTRACT_VERSION = "1.1.0"

TOOL_POLICIES = (
    ToolPolicy(name="hyperv.host.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.vm.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.vm.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.switch.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.checkpoint.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.vhd.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.replication.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.event.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="hyperv.vm.diagnose", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(
        name="hyperv.checkpoint.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="hyperv.checkpoint.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        requires_approval=True,
    ),
    ToolPolicy(
        name="hyperv.checkpoint.verify",
        phase=OperationPhase.VERIFY,
        risk=RiskLevel.READ_ONLY,
    ),
)


def capabilities(
    budget_limits: QueryBudgetLimits,
    connector_policy: ReadOnlyConnectorPolicy,
    *,
    require_jea: bool,
    checkpoint_writes_enabled: bool = False,
    checkpoint_max_existing: int = 8,
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
            "writes_enabled": checkpoint_writes_enabled,
            "arbitrary_powershell": False,
            "arbitrary_wmi_or_cim": False,
            "guest_command": False,
            "vm_state_mutation": False,
            "checkpoint_creation_mutation": checkpoint_writes_enabled,
            "checkpoint_restore_mutation": False,
            "checkpoint_delete_mutation": False,
            "checkpoint_type_required": "ProductionOnly",
            "checkpoint_max_existing": checkpoint_max_existing,
            "separate_checkpoint_jea_endpoint_required": True,
            "configured_target_alias_required": True,
            "aggregate_before_vm_fan_out": True,
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
