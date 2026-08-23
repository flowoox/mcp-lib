from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT = "flowoox.windows-diagnostics"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="windows.host.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.services.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.processes.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.features.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.events.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.certificates.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.updates.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.hyperv-host.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="windows.diagnostics.bundle", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)


def capabilities(
    connector_policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    target_ids: list[str],
    allowed_event_logs: list[str],
    remote_requires_jea: bool,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "connector": redacted_connector_metadata(
                connector_policy,
                backend_kind="windows-powershell-winrm",
                extra={"remote_requires_jea": remote_requires_jea},
            ),
            "logical_targets": sorted(target_ids),
            "allowed_event_logs": sorted(allowed_event_logs),
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_powershell": False,
            "arbitrary_cmdlet": False,
            "arbitrary_event_log": False,
            "arbitrary_certificate_path": False,
            "raw_process_output": False,
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
