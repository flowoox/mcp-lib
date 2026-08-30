from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.freshdesk-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    max_page_number: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="freshdesk-rest-v2",
            extra={
                "authentication": "api_key_basic",
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "arbitrarySearchQueriesAllowed": False,
                "maxPageNumber": max_page_number,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": sorted(policy.allowed_operations),
        "safety": {
            "aggregateBeforeFanOut": True,
            "requesterPiiReturned": False,
            "agentIdentityReturned": False,
            "messageBodiesReturned": False,
            "attachmentContentReturned": False,
            "customFieldsReturned": False,
            "ticketMutationsExposed": False,
            "conversationMutationsExposed": False,
            "callerSelectedUrlOrMethod": False,
            "genericSearchDslExposed": False,
        },
    }
