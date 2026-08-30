from __future__ import annotations

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from freshdesk_mcp.contract import capabilities
from freshdesk_mcp.server import _CONNECTOR_OPERATIONS


def test_contract_is_read_only_and_redacts_sensitive_helpdesk_data() -> None:
    policy = ReadOnlyConnectorPolicy(
        connector_name="freshdesk.rest-v2.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        max_page_size=100,
    )
    payload = capabilities(policy, QueryBudgetLimits(), max_page_number=50)
    assert payload["mode"] == "read_only"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["arbitraryApiPathsAllowed"] is False
    assert payload["backend"]["arbitrarySearchQueriesAllowed"] is False
    assert payload["safety"]["requesterPiiReturned"] is False
    assert payload["safety"]["agentIdentityReturned"] is False
    assert payload["safety"]["messageBodiesReturned"] is False
    assert payload["safety"]["attachmentContentReturned"] is False
    assert sorted(payload["operations"]) == sorted(_CONNECTOR_OPERATIONS)


def test_operation_surface_contains_only_fixed_get_observations() -> None:
    assert frozenset(
        {
            "freshdesk.tickets.list",
            "freshdesk.tickets.get",
            "freshdesk.tickets.conversations",
        }
    ) == _CONNECTOR_OPERATIONS
