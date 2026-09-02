from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.operations import (
    AuditEvent,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
)
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits
from mcp_common.read_only_connector import (
    PageRequest,
    ReadOnlyConnector,
    ReadOnlyConnectorPolicy,
    ReadOnlyQuery,
    SampleRequest,
)

from .client import WazuhIndexerReadOnlyTransport, WazuhServerReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .version_gate import (
    VersionGatedWazuhIndexerTransport,
    VersionGatedWazuhServerTransport,
    WazuhRuntimeVersionGate,
)

_SERVER_OPERATIONS = frozenset(
    {
        "wazuh.api.info",
        "wazuh.agents.summary",
        "wazuh.agents.list",
        "wazuh.manager.status",
        "wazuh.manager.logs.summary",
    }
)
_INDEXER_OPERATIONS = frozenset(
    {
        "wazuh.alerts.summary",
        "wazuh.vulnerabilities.summary",
    }
)


def _connector_policy(
    settings: Settings,
    *,
    connector_name: str,
    operations: frozenset[str],
) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name=connector_name,
        allowed_operations=operations,
        require_read_only_backend=True,
        max_page_size=settings.wazuh_max_page_size,
        max_sample_size=settings.wazuh_max_sample_size,
        request_timeout_seconds=settings.wazuh_request_timeout_seconds,
        max_response_bytes=settings.wazuh_max_response_bytes,
        max_concurrency=settings.wazuh_max_concurrency,
        rate_limit_per_second=settings.wazuh_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.wazuh_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.wazuh_budget_max_requests,
        max_items=settings.wazuh_budget_max_items,
        max_response_bytes=settings.wazuh_budget_max_response_bytes,
        max_fan_out=settings.wazuh_budget_max_fan_out,
        total_timeout_seconds=settings.wazuh_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="wazuh-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="wazuh-mcp")


def _reason(value: str) -> str:
    normalized = value.strip()
    if not 1 <= len(normalized) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return normalized


def _response(
    operation: str,
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    output: dict[str, Any],
    budget: QueryBudget,
    target: str = "wazuh:environment",
) -> dict[str, Any]:
    context = _context(actor, correlation_id)
    result_output = dict(output)
    result_output["queryBudget"] = budget.snapshot().model_dump(mode="json")
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        status=OperationStatus.SUCCEEDED,
        context=context,
        output=result_output,
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=target,
        status=OperationStatus.SUCCEEDED,
        metadata={"reason": _reason(reason)},
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


async def _page(
    connector: ReadOnlyConnector,
    budget: QueryBudget,
    *,
    operation: str,
    limit: int,
    cursor: str | None = None,
    parameters: dict[str, Any] | None = None,
    sample_size: int | None = None,
    sample_strategy: Literal["head", "even"] = "even",
) -> dict[str, Any]:
    sample = (
        SampleRequest(size=sample_size, strategy=sample_strategy)
        if sample_size is not None
        else None
    )
    result = await connector.execute(
        ReadOnlyQuery(
            operation=operation,
            parameters=parameters or {},
            page=PageRequest(limit=limit, cursor=cursor),
            sample=sample,
            aggregated=True,
        ),
        budget,
    )
    return {
        "items": result.items,
        "returned": len(result.items),
        "nextCursor": result.next_cursor,
        "truncated": result.truncated,
        "sampled": result.sampled,
        "cacheHint": result.cache_hint.model_dump(mode="json") if result.cache_hint else None,
    }


def create_server(
    settings: Settings | None = None,
    server_connector: ReadOnlyConnector | None = None,
    indexer_connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    server_policy = _connector_policy(
        settings,
        connector_name="wazuh.server.readonly",
        operations=_SERVER_OPERATIONS,
    )
    indexer_policy = _connector_policy(
        settings,
        connector_name="wazuh.indexer.readonly",
        operations=_INDEXER_OPERATIONS,
    )
    budget_limits = _budget_limits(settings)

    if server_connector is None or indexer_connector is None:
        raw_server_transport = WazuhServerReadOnlyTransport(settings)
        runtime_gate = WazuhRuntimeVersionGate(raw_server_transport)
    if server_connector is None:
        server_connector = ReadOnlyConnector(
            server_policy,
            VersionGatedWazuhServerTransport(raw_server_transport, runtime_gate),
        )
    if indexer_connector is None:
        indexer_connector = ReadOnlyConnector(
            indexer_policy,
            VersionGatedWazuhIndexerTransport(
                WazuhIndexerReadOnlyTransport(settings),
                runtime_gate,
            ),
        )

    security = build_mcp_server_security(settings, service_hosts=("mcp-wazuh",))
    mcp = FastMCP(
        "Flowoox Wazuh Diagnostics MCP",
        instructions=(
            "Bounded read-only Wazuh 4.14 diagnostics using the Wazuh server API and "
            "aggregation-only Wazuh indexer searches. Raw alert/vulnerability documents, "
            "agent IP/enrollment data, arbitrary WQL/OpenSearch DSL, active response, agent "
            "enrollment/removal, restarts and configuration/index mutations are not exposed."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        return capabilities(
            server_connector.policy,
            indexer_connector.policy,
            budget_limits,
            max_offset=settings.wazuh_max_offset,
            max_alert_window_minutes=settings.wazuh_max_alert_window_minutes,
        )

    @mcp.tool()
    async def wazuh_get_health_summary(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        api = await _page(server_connector, budget, operation="wazuh.api.info", limit=1)
        agents = await _page(server_connector, budget, operation="wazuh.agents.summary", limit=1)
        manager = await _page(server_connector, budget, operation="wazuh.manager.status", limit=1)
        logs = await _page(
            server_connector,
            budget,
            operation="wazuh.manager.logs.summary",
            limit=32,
        )
        return _response(
            "wazuh.health.summary",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"api": api, "agents": agents, "manager": manager, "managerLogSummary": logs},
            budget=budget,
        )

    @mcp.tool()
    async def wazuh_list_agents(
        actor: str,
        reason: str,
        status: Literal["active", "disconnected", "pending", "never_connected"] | None = None,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters: dict[str, Any] = {}
        if status is not None:
            parameters["status"] = status
        page = await _page(
            server_connector,
            budget,
            operation="wazuh.agents.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "wazuh.agents.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="wazuh:agents",
        )

    @mcp.tool()
    async def wazuh_get_alert_summary(
        actor: str,
        reason: str,
        window_minutes: int = 60,
        minimum_rule_level: int = 3,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            indexer_connector,
            budget,
            operation="wazuh.alerts.summary",
            limit=1,
            parameters={"window_minutes": window_minutes, "minimum_rule_level": minimum_rule_level},
        )
        return _response(
            "wazuh.alerts.summary",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="wazuh:alerts",
        )

    @mcp.tool()
    async def wazuh_get_vulnerability_summary(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            indexer_connector,
            budget,
            operation="wazuh.vulnerabilities.summary",
            limit=1,
        )
        return _response(
            "wazuh.vulnerabilities.summary",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="wazuh:vulnerabilities",
        )

    @mcp.tool()
    async def wazuh_diagnostic_bundle(
        actor: str,
        reason: str,
        alert_window_minutes: int = 60,
        minimum_rule_level: int = 8,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        agents = await _page(server_connector, budget, operation="wazuh.agents.summary", limit=1)
        manager = await _page(server_connector, budget, operation="wazuh.manager.status", limit=1)
        alerts = await _page(
            indexer_connector,
            budget,
            operation="wazuh.alerts.summary",
            limit=1,
            parameters={
                "window_minutes": alert_window_minutes,
                "minimum_rule_level": minimum_rule_level,
            },
        )
        vulnerabilities = await _page(
            indexer_connector,
            budget,
            operation="wazuh.vulnerabilities.summary",
            limit=1,
        )
        return _response(
            "wazuh.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "agentStatus": agents,
                "managerStatus": manager,
                "alertSummary": alerts,
                "vulnerabilitySummary": vulnerabilities,
            },
            budget=budget,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
