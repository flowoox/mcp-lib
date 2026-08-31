from __future__ import annotations

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy

from veeam_mcp.contract import capabilities
from veeam_mcp.server import _CONNECTOR_OPERATIONS


def test_contract_is_read_only_and_minimizes_sensitive_backup_data() -> None:
    policy = ReadOnlyConnectorPolicy(
        connector_name="veeam.vbr13.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        max_page_size=100,
    )
    payload = capabilities(
        policy,
        QueryBudgetLimits(),
        max_offset=5_000,
        max_history_hours=720,
    )
    assert payload["mode"] == "read_only"
    assert payload["backend"]["requiredBackendRole"] == "Backup Viewer"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["arbitraryApiPathsAllowed"] is False
    assert payload["backend"]["arbitraryFiltersAllowed"] is False
    assert payload["safety"]["repositoryPathsReturned"] is False
    assert payload["safety"]["repositoryHostNamesReturned"] is False
    assert payload["safety"]["sessionInitiatorReturned"] is False
    assert payload["safety"]["sessionMessageReturned"] is False
    assert payload["safety"]["credentialInventoryReturned"] is False


def test_operation_surface_contains_only_fixed_get_observations() -> None:
    assert frozenset(
        {
            "veeam.jobs.states",
            "veeam.sessions.list",
            "veeam.repositories.states",
            "veeam.backups.list",
            "veeam.restore_points.list",
        }
    ) == _CONNECTOR_OPERATIONS
