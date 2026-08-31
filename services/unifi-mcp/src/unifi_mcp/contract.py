from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.unifi-network-diagnostics"
CONTRACT_VERSION = "1.0"
VENDOR_API_VERSION = "10.0.162"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    max_offset: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "vendorApiDocumentedVersion": VENDOR_API_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="unifi-network-integration-v1",
            extra={
                "authentication": "x_api_key",
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "arbitraryFiltersAllowed": False,
                "maxOffset": max_offset,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "deviceMacAddressesReturned": False,
            "deviceIpAddressesReturned": False,
            "clientMacAddressesReturned": False,
            "clientIpAddressesReturned": False,
            "clientNamesReturned": False,
            "configurationIdentifiersReturned": False,
            "writeActionsExposed": False,
            "callerSelectedUrlOrMethod": False,
            "genericFilterDslExposed": False,
        },
    }
