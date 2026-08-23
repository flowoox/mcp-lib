from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT = "flowoox.fortigate-diagnostics"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(name="fortigate.system.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.interfaces.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.routes.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.policies.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.addresses.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.ipsec.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fortigate.diagnostics.bundle", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)

_DESCRIPTIONS = {
    "fortigate.system.observe": "Return projected system status and HA configuration without raw configuration payloads.",
    "fortigate.interfaces.list": "Return a bounded projected interface inventory for an allowlisted VDOM.",
    "fortigate.routes.list": "Return a bounded projected static-route inventory for an allowlisted VDOM.",
    "fortigate.policies.list": "Return a bounded projected IPv4 firewall-policy inventory for an allowlisted VDOM.",
    "fortigate.addresses.list": "Return a bounded projected firewall-address inventory for an allowlisted VDOM.",
    "fortigate.ipsec.list": "Return a bounded projected IPsec phase1-interface inventory for an allowlisted VDOM.",
    "fortigate.diagnostics.bundle": "Aggregate bounded system, HA, interface, route, policy and IPsec observations under one query budget.",
}


def capabilities(connector_policy: ReadOnlyConnectorPolicy, budget_limits: QueryBudgetLimits) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "connector": redacted_connector_metadata(connector_policy, backend_kind="fortios-rest-api"),
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_api_path": False,
            "arbitrary_http_method": False,
            "arbitrary_filter": False,
            "arbitrary_format": False,
            "raw_configuration_payloads": False,
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
