from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.n8n-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    workflow_allowlist_configured: bool,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="n8n-public-api-v1",
            extra={
                "authentication": "x-n8n-api-key",
                "workflowAllowlistConfigured": workflow_allowlist_configured,
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "projectIdReliedOnForAuthorization": False,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": [
            "n8n.workflows.list",
            "n8n.executions.list",
            "n8n.executions.get",
        ],
        "safety": {
            "aggregateBeforeFanOut": True,
            "workflowDefinitionsReturned": False,
            "executionPayloadDataReturned": False,
            "credentialValuesReturned": False,
            "workflowTriggerExposed": False,
            "workflowMutationExposed": False,
            "callerSelectedUrlOrMethod": False,
        },
    }
