from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.exchange-m365"
CONTRACT_VERSION = "1.1"


def capabilities(
    exchange_policy: ReadOnlyConnectorPolicy,
    graph_policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    return_domain_names: bool,
    mailbox_debug_enabled: bool = False,
    writes_enabled: bool = False,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "approved_management" if writes_enabled else "read_only",
        "backends": {
            "exchangeOnline": redacted_connector_metadata(
                exchange_policy,
                backend_kind="exchange-online-powershell-app-only",
                extra={
                    "authentication": "certificate_app_only",
                    "exchangeManageAsAppRequired": True,
                    "viewOnlyExchangeRbacRequired": True,
                    "commandImportAllowlisted": True,
                    "arbitraryPowerShellAllowed": False,
                    "previewAdminApiUsed": False,
                    "mailboxDebugEnabled": mailbox_debug_enabled,
                    "writeToolsRegistered": writes_enabled,
                },
            ),
            "microsoftGraph": redacted_connector_metadata(
                graph_policy,
                backend_kind="microsoft-graph-v1-service-health",
                extra={
                    "authentication": "oauth2_client_credentials",
                    "applicationPermission": "ServiceHealth.Read.All",
                    "arbitraryGraphPathsAllowed": False,
                    "writeToolsRegistered": False,
                },
            ),
        },
        "mailboxManagement": {
            "enabled": writes_enabled,
            "mailboxTypes": ["shared"] if writes_enabled else [],
            "separateManagementIdentityRequired": True,
            "exchangeApplicationRbacAttestationRequired": True,
            "exactDomainAllowlistRequired": True,
            "idempotencyRequired": True,
            "signedApprovalRequired": True,
            "postChangeVerificationRequired": True,
            "arbitraryRecipientMutationAllowed": False,
        },
        "queryBudget": budget_limits.model_dump(mode="json"),
        "safety": {
            "aggregateBeforeFanOut": True,
            "domainNamesReturned": return_domain_names,
            "connectorNamesReturned": False,
            "senderIpAddressesReturned": False,
            "certificateSubjectsReturned": False,
            "smartHostsReturned": False,
            "mailboxRecipientsEnumerated": False,
            "mailboxDebugExactIdentityOnly": mailbox_debug_enabled,
            "messageBodiesReturned": False,
            "attachmentsReturned": False,
            "mailboxExportOrEdiscoveryExposed": False,
            "messageTraceExposed": False,
            "callerSelectedPowerShell": False,
            "callerSelectedGraphPathsOrFilters": False,
            "mutationsExposed": writes_enabled,
        },
    }
