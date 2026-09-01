from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.wazuh-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    server_policy: ReadOnlyConnectorPolicy,
    indexer_policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    max_offset: int,
    max_alert_window_minutes: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "verifiedVendorContract": {
            "wazuhServerApi": "4.14.7",
            "wazuhIndexer": "4.14.x",
        },
        "backends": {
            "server": redacted_connector_metadata(
                server_policy,
                backend_kind="wazuh-server-api",
                extra={
                    "authentication": "jwt_from_basic_auth",
                    "requiredBackendRole": "readonly",
                    "authenticationPostIsInternalOnly": True,
                    "redirectsAllowed": False,
                    "arbitraryApiPathsAllowed": False,
                    "arbitraryWqlAllowed": False,
                    "maxOffset": max_offset,
                    "writeToolsRegistered": False,
                },
            ),
            "indexer": redacted_connector_metadata(
                indexer_policy,
                backend_kind="wazuh-indexer-api",
                extra={
                    "authentication": "basic_auth",
                    "requiredIndexPermissions": [
                        "cluster_composite_ops_ro",
                        "read:wazuh-alerts-*",
                        "read:wazuh-states-vulnerabilities-*",
                    ],
                    "redirectsAllowed": False,
                    "arbitraryIndexPatternsAllowed": False,
                    "arbitrarySearchDslAllowed": False,
                    "rawDocumentsReturned": False,
                    "maxAlertWindowMinutes": max_alert_window_minutes,
                    "writeToolsRegistered": False,
                },
            ),
        },
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(
            set(server_policy.allowed_operations) | set(indexer_policy.allowed_operations)
        ),
        "safety": {
            "aggregateBeforeFanOut": True,
            "agentIpReturned": False,
            "agentEnrollmentDataReturned": False,
            "rawAlertDocumentsReturned": False,
            "rawVulnerabilityDocumentsReturned": False,
            "activeResponseExposed": False,
            "agentEnrollmentRemovalExposed": False,
            "managerRestartExposed": False,
            "configurationMutationExposed": False,
            "indexMutationExposed": False,
            "callerSelectedUrlOrMethod": False,
        },
    }
