from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.pki-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="windows-adcs-jea",
            extra={
                "authentication": "kerberos_winrm_jea",
                "viewCaDatabasePermissionRequired": True,
                "certutilUsed": False,
                "arbitraryPowerShellAllowed": False,
                "arbitraryComObjectsAllowed": False,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "logicalTargetAliasesOnly": True,
            "caConfigurationReturned": False,
            "requesterIdentityReturned": False,
            "certificateSubjectReturned": False,
            "certificateSerialReturned": False,
            "certificateBodiesReturned": False,
            "privateKeysReturned": False,
            "publicationUrlsReturned": False,
            "certificateTemplateObjectsReturned": False,
            "issuanceOrRevocationExposed": False,
            "caOrTemplateMutationExposed": False,
            "callerSelectedPowerShell": False,
            "callerSelectedDatabaseColumns": False,
            "callerSelectedDatabaseRestrictions": False,
        },
    }
