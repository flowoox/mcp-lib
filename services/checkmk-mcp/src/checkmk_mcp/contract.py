from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.checkmk-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    backend_role: str,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="checkmk-rest-1.0",
            extra={
                "authentication": "automation_user_bearer",
                "backendRoleAttested": bool(backend_role.strip()),
                "redirectsAllowed": False,
                "stableApiOnly": True,
                "unstableApiAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "arbitraryLivestatusQueriesAllowed": False,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "problemOnlyMonitoringQueries": True,
            "fixedColumns": True,
            "hostAddressesReturned": False,
            "contactsReturned": False,
            "pluginOutputReturned": False,
            "performanceDataReturned": False,
            "commentsReturned": False,
            "configurationEndpointsExposed": False,
            "downtimeOrAcknowledgementWritesExposed": False,
            "activationOrDiscoveryActionsExposed": False,
            "callerSelectedUrlOrMethod": False,
            "callerSelectedLivestatusDsl": False,
        },
    }
