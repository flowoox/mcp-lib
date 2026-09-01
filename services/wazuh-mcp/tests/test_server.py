from __future__ import annotations

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from wazuh_mcp.contract import capabilities
from wazuh_mcp.server import _INDEXER_OPERATIONS, _SERVER_OPERATIONS


def test_contract_is_read_only_and_excludes_high_risk_surfaces() -> None:
    server_policy = ReadOnlyConnectorPolicy(
        connector_name="wazuh.server.readonly",
        allowed_operations=_SERVER_OPERATIONS,
        max_page_size=100,
    )
    indexer_policy = ReadOnlyConnectorPolicy(
        connector_name="wazuh.indexer.readonly",
        allowed_operations=_INDEXER_OPERATIONS,
        max_page_size=100,
    )
    payload = capabilities(
        server_policy,
        indexer_policy,
        QueryBudgetLimits(),
        max_offset=10_000,
        max_alert_window_minutes=1_440,
    )
    assert payload["mode"] == "read_only"
    assert payload["backends"]["server"]["requiredBackendRole"] == "readonly"
    assert payload["backends"]["server"]["writeToolsRegistered"] is False
    assert payload["backends"]["server"]["arbitraryWqlAllowed"] is False
    assert payload["backends"]["indexer"]["arbitrarySearchDslAllowed"] is False
    assert payload["backends"]["indexer"]["rawDocumentsReturned"] is False
    assert payload["safety"]["agentIpReturned"] is False
    assert payload["safety"]["rawAlertDocumentsReturned"] is False
    assert payload["safety"]["rawVulnerabilityDocumentsReturned"] is False
    assert payload["safety"]["activeResponseExposed"] is False
    assert payload["safety"]["agentEnrollmentRemovalExposed"] is False
    assert payload["safety"]["configurationMutationExposed"] is False
    assert payload["safety"]["indexMutationExposed"] is False


def test_operation_surface_contains_only_fixed_observations() -> None:
    assert frozenset(
        {
            "wazuh.api.info",
            "wazuh.agents.summary",
            "wazuh.agents.list",
            "wazuh.manager.status",
            "wazuh.manager.logs.summary",
        }
    ) == _SERVER_OPERATIONS
    assert frozenset(
        {
            "wazuh.alerts.summary",
            "wazuh.vulnerabilities.summary",
        }
    ) == _INDEXER_OPERATIONS
