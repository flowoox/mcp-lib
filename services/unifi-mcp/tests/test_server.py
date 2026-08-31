from __future__ import annotations

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from unifi_mcp.contract import capabilities
from unifi_mcp.server import _CONNECTOR_OPERATIONS


def test_contract_is_read_only_and_minimizes_network_identity_data() -> None:
    policy = ReadOnlyConnectorPolicy(
        connector_name="unifi.network-integration.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        max_page_size=100,
    )
    payload = capabilities(policy, QueryBudgetLimits(), max_offset=5_000)
    assert payload["mode"] == "read_only"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["arbitraryApiPathsAllowed"] is False
    assert payload["backend"]["arbitraryFiltersAllowed"] is False
    assert payload["safety"]["deviceMacAddressesReturned"] is False
    assert payload["safety"]["deviceIpAddressesReturned"] is False
    assert payload["safety"]["clientMacAddressesReturned"] is False
    assert payload["safety"]["clientIpAddressesReturned"] is False
    assert payload["safety"]["clientNamesReturned"] is False
    assert sorted(payload["operations"]) == sorted(_CONNECTOR_OPERATIONS)


def test_operation_surface_contains_only_fixed_get_observations() -> None:
    assert _CONNECTOR_OPERATIONS == frozenset(
        {
            "unifi.application.info",
            "unifi.sites.list",
            "unifi.devices.list",
            "unifi.devices.get",
            "unifi.devices.statistics.latest",
            "unifi.clients.list",
            "unifi.clients.get",
        }
    )
