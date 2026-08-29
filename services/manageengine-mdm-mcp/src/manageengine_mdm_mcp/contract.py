from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.manageengine-mdm-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    auth_mode: str,
    customer_scope_configured: bool,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="manageengine-mdm-plus-rest-v1",
            extra={
                "authentication": auth_mode,
                "customerScopeConfigured": customer_scope_configured,
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "hardwareIdentifiersReturned": False,
            "assignedUserPiiReturned": False,
            "locationDataReturned": False,
            "firmwarePasswordsReturned": False,
            "rawDeviceDetailsReturned": False,
            "commandInitiatorIdentityReturned": False,
            "deviceActionsExposed": False,
            "callerSelectedUrlOrMethod": False,
        },
    }
