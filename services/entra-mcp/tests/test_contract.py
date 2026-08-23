from entra_mcp.config import Settings
from entra_mcp.contract import TOOL_POLICIES, capabilities
from entra_mcp.server import _budget_limits, _connector_policy


def test_contract_is_read_only_and_product_neutral() -> None:
    settings = Settings()
    data = capabilities(_connector_policy(settings), _budget_limits(settings), cloud="global")
    assert data["runtime"]["writes_enabled"] is False
    assert data["runtime"]["arbitrary_graph_path"] is False
    assert data["runtime"]["arbitrary_odata"] is False
    assert data["runtime"]["delegated_user_context"] is False
    assert data["runtime"]["raw_graph_payloads"] is False
    assert "tenant_id" not in str(data).casefold()
    assert "client_id" not in str(data).casefold()
    assert all(policy.risk.value == "read_only" for policy in TOOL_POLICIES)
    assert all(policy.phase.value == "observe" for policy in TOOL_POLICIES)


def test_contract_advertises_resource_specific_permissions() -> None:
    data = capabilities(_connector_policy(Settings()), _budget_limits(Settings()), cloud="global")
    permissions = set(data["requiredApplicationPermissions"])
    assert "User.Read.All" in permissions
    assert "Device.Read.All" in permissions
    assert "Application.Read.All" in permissions
    assert "RoleManagement.Read.Directory" in permissions
    assert "Policy.Read.All" in permissions
    assert "Directory.Read.All" not in permissions
