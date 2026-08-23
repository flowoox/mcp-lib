from fortigate_mcp.config import Settings
from fortigate_mcp.contract import TOOL_POLICIES, capabilities
from fortigate_mcp.server import _budget_limits, _connector_policy


def test_contract_is_explicit_read_only_and_redacts_topology() -> None:
    settings = Settings()
    data = capabilities(_connector_policy(settings), _budget_limits(settings))
    assert data["runtime"]["writes_enabled"] is False
    assert data["runtime"]["arbitrary_api_path"] is False
    assert data["runtime"]["arbitrary_filter"] is False
    assert data["runtime"]["raw_configuration_payloads"] is False
    assert "base_url" not in str(data).casefold()
    assert all(policy.risk.value == "read_only" for policy in TOOL_POLICIES)
    assert all(policy.phase.value == "observe" for policy in TOOL_POLICIES)
