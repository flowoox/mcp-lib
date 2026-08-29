from __future__ import annotations

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from manageengine_mdm_mcp.contract import capabilities
from manageengine_mdm_mcp.server import _CONNECTOR_OPERATIONS


def test_contract_is_read_only_and_redacts_backend_details() -> None:
    policy = ReadOnlyConnectorPolicy(
        connector_name="manageengine-mdm.rest-v1.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        max_page_size=100,
    )
    payload = capabilities(
        policy,
        QueryBudgetLimits(),
        auth_mode="cloud_oauth",
        customer_scope_configured=True,
    )
    assert payload["mode"] == "read_only"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["arbitraryApiPathsAllowed"] is False
    assert payload["safety"]["assignedUserPiiReturned"] is False
    assert payload["safety"]["locationDataReturned"] is False
    assert sorted(payload["operations"]) == sorted(_CONNECTOR_OPERATIONS)


def test_operation_surface_contains_only_inventory_gets() -> None:
    assert _CONNECTOR_OPERATIONS == frozenset(
        {
            "manageengine_mdm.devices.list",
            "manageengine_mdm.devices.scan_status",
            "manageengine_mdm.devices.command_history",
        }
    )
