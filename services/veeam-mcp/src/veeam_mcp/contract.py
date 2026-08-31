from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.veeam-backup-diagnostics"
CONTRACT_VERSION = "1.0"
VENDOR_API_VERSION = "1.3-rev2"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    max_offset: int,
    max_history_hours: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "vendorApiVersion": VENDOR_API_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="veeam-vbr13-rest",
            extra={
                "authentication": "oauth2_password_grant_to_bearer",
                "requiredBackendRole": "Backup Viewer",
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "arbitraryFiltersAllowed": False,
                "maxOffset": max_offset,
                "maxHistoryHours": max_history_hours,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "repositoryPathsReturned": False,
            "repositoryHostNamesReturned": False,
            "sessionInitiatorReturned": False,
            "sessionMessageReturned": False,
            "credentialInventoryReturned": False,
            "restoreActionsExposed": False,
            "jobActionsExposed": False,
            "configurationWritesExposed": False,
            "callerSelectedUrlOrMethod": False,
            "genericFilterDslExposed": False,
        },
    }
