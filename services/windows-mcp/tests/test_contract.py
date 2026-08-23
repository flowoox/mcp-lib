from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from windows_mcp.contract import CONTRACT, CONTRACT_VERSION, TOOL_POLICIES, capabilities


def test_contract_is_read_only_and_explicit() -> None:
    assert CONTRACT == "flowoox.windows-diagnostics"
    assert CONTRACT_VERSION == "1.0.0"
    assert len(TOOL_POLICIES) == 9
    assert all(policy.risk.value == "read_only" for policy in TOOL_POLICIES)
    assert all(not policy.requires_approval for policy in TOOL_POLICIES)


def test_capabilities_redact_backend_and_disable_arbitrary_execution() -> None:
    policy = ReadOnlyConnectorPolicy(
        connector_name="windows.powershell.readonly",
        allowed_operations=frozenset({"windows.host.inventory"}),
    )
    result = capabilities(
        policy,
        QueryBudgetLimits(),
        target_ids=["local", "dc01"],
        allowed_event_logs=["System"],
        remote_requires_jea=True,
    )
    assert result["runtime"]["writes_enabled"] is False
    assert result["runtime"]["arbitrary_powershell"] is False
    assert result["runtime"]["arbitrary_cmdlet"] is False
    assert result["runtime"]["connector"]["backend_mode"] == "read_only"
    assert result["runtime"]["logical_targets"] == ["dc01", "local"]
