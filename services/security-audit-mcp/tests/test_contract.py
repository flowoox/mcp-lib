from mcp_common.operations import OperationPhase, RiskLevel
from mcp_common.query_budget import QueryBudgetLimits

from security_audit_mcp.contract import TOOL_POLICIES, capabilities


def test_contract_is_explicitly_read_only() -> None:
    assert {policy.name for policy in TOOL_POLICIES} == {"security.audit.evaluate"}
    assert all(policy.phase == OperationPhase.OBSERVE for policy in TOOL_POLICIES)
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in TOOL_POLICIES)
    assert all(not policy.requires_approval for policy in TOOL_POLICIES)


def test_capabilities_publish_fixed_controls_without_backend_surface() -> None:
    payload = capabilities(QueryBudgetLimits(), max_evidence=100)
    runtime = payload["runtime"]
    assert runtime["writes_enabled"] is False
    assert runtime["direct_privileged_backend"] is False
    assert runtime["arbitrary_policy_input"] is False
    assert runtime["arbitrary_query_or_command"] is False
    assert runtime["max_evidence_per_call"] == 100
    assert len(payload["controls"]) >= 5
    assert {item["id"] for item in payload["capabilities"]} == {"security.audit.evaluate"}
