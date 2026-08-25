from __future__ import annotations

from typing import Any

from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import ReadOnlyConnectorPolicy, redacted_connector_metadata

CONTRACT_NAME = "flowoox.prtg-diagnostics"
CONTRACT_VERSION = "1.0"


def capabilities(
    policy: ReadOnlyConnectorPolicy,
    budget_limits: QueryBudgetLimits,
    *,
    historic_max_window_hours: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT_NAME,
        "version": CONTRACT_VERSION,
        "mode": "read_only",
        "backend": redacted_connector_metadata(
            policy,
            backend_kind="prtg-http-api-v1",
            extra={
                "authentication": "authorization-bearer-api-key",
                "historicMaxWindowHours": historic_max_window_hours,
                "historicRateLimit": "max-5-requests-per-minute",
                "redirectsAllowed": False,
                "arbitraryApiPathsAllowed": False,
                "writeToolsRegistered": False,
            },
        ),
        "queryBudget": budget_limits.model_dump(mode="json"),
        "operations": [
            "prtg.system.health-status",
            "prtg.system.health-data",
            "prtg.devices.list",
            "prtg.sensors.list",
            "prtg.alarms.list",
            "prtg.channels.list",
            "prtg.messages.list",
            "prtg.historic.sensor",
        ],
        "safety": {
            "aggregateBeforeFanOut": True,
            "historicRefreshNowExposed": False,
            "historicUnboundedExportExposed": False,
            "credentialValuesReturned": False,
            "callerSelectedUrlOrMethod": False,
        },
    }
