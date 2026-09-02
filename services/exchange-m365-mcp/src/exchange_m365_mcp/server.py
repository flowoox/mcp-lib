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

from .config import Settings
from .contract import capabilities
from .exchange_transport import ExchangeOnlineReadOnlyTransport
from .graph_transport import MicrosoftGraphServiceHealthTransport

_EXCHANGE_OPERATIONS = frozenset(
    {
        "exchange.organization.get",
        "exchange.accepted_domains.list",
        "exchange.remote_domains.list",
        "exchange.inbound_connectors.list",
        "exchange.outbound_connectors.list",
        "exchange.transport_config.get",
    }
)
_GRAPH_OPERATIONS = frozenset(
    {
        "m365.service_health.list",
        "m365.exchange_issues.list",
    }
)


def _exchange_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="exchange.online.powershell.readonly",
        allowed_operations=_EXCHANGE_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.exchange_max_page_size,
        max_sample_size=settings.exchange_max_sample_size,
        request_timeout_seconds=settings.exchange_request_timeout_seconds,
        max_response_bytes=settings.exchange_max_response_bytes,
        max_concurrency=settings.exchange_max_concurrency,
        rate_limit_per_second=settings.exchange_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.exchange_cache_max_age_seconds,
    )


def _graph_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="microsoft.graph.service-health.readonly",
        allowed_operations=_GRAPH_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.graph_max_page_size,
        max_sample_size=settings.graph_max_sample_size,
        request_timeout_seconds=settings.graph_request_timeout_seconds,
        max_response_bytes=settings.graph_max_response_bytes,
        max_concurrency=settings.graph_max_concurrency,
        rate_limit_per_second=settings.graph_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.graph_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.m365_budget_max_requests,
        max_items=settings.m365_budget_max_items,
        max_response_bytes=settings.m365_budget_max_response_bytes,
        max_fan_out=settings.m365_budget_max_fan_out,
        total_timeout_seconds=settings.m365_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="exchange-m365-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="exchange-m365-mcp")


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
    target: str = "m365:tenant",
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
            page=PageRequest(limit=limit),
            sample=sample,
            aggregated=True,
        ),
        budget,
    )
    return {
        "items": result.items,
        "returned": len(result.items),
        "truncated": result.truncated,
        "sampled": result.sampled,
        "cacheHint": result.cache_hint.model_dump(mode="json") if result.cache_hint else None,
    }


def create_server(
    settings: Settings | None = None,
    exchange_connector: ReadOnlyConnector | None = None,
    graph_connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    exchange_policy = _exchange_policy(settings)
    graph_policy = _graph_policy(settings)
    budget_limits = _budget_limits(settings)
    exchange_connector = exchange_connector or ReadOnlyConnector(
        exchange_policy,
        ExchangeOnlineReadOnlyTransport(settings),
    )
    graph_connector = graph_connector or ReadOnlyConnector(
        graph_policy,
        MicrosoftGraphServiceHealthTransport(settings),
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-exchange-m365",))
    mcp = FastMCP(
        "Flowoox Exchange Online and Microsoft 365 Diagnostics MCP",
        instructions=(
            "Bounded read-only Exchange Online configuration and Microsoft 365 service-health "
            "diagnostics. Exchange Online uses certificate app-only authentication plus a "
            "deployment-attested view-only Exchange RBAC assignment and imports only fixed Get-* "
            "cmdlets. Microsoft Graph is limited to v1.0 ServiceHealth.Read.All. Mailbox contents, "
            "message bodies, recipients, traces, eDiscovery, arbitrary PowerShell/API paths and all "
            "mutations are not exposed."
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
            exchange_connector.policy,
            graph_connector.policy,
            budget_limits,
            return_domain_names=settings.exchange_return_domain_names,
        )

    @mcp.tool()
    async def exchange_get_organization(actor: str, reason: str, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.organization.get", limit=1)
        return _response("exchange.organization.get", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:organization")

    @mcp.tool()
    async def exchange_list_accepted_domains(actor: str, reason: str, limit: int = 50, sample_size: int | None = None, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.accepted_domains.list", limit=limit, sample_size=sample_size)
        return _response("exchange.accepted_domains.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:accepted-domains")

    @mcp.tool()
    async def exchange_list_remote_domains(actor: str, reason: str, limit: int = 50, sample_size: int | None = None, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.remote_domains.list", limit=limit, sample_size=sample_size)
        return _response("exchange.remote_domains.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:remote-domains")

    @mcp.tool()
    async def exchange_list_inbound_connectors(actor: str, reason: str, limit: int = 50, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.inbound_connectors.list", limit=limit)
        return _response("exchange.inbound_connectors.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:inbound-connectors")

    @mcp.tool()
    async def exchange_list_outbound_connectors(actor: str, reason: str, limit: int = 50, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.outbound_connectors.list", limit=limit)
        return _response("exchange.outbound_connectors.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:outbound-connectors")

    @mcp.tool()
    async def exchange_get_transport_config(actor: str, reason: str, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(exchange_connector, budget, operation="exchange.transport_config.get", limit=1)
        return _response("exchange.transport_config.get", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="exchange:transport-config")

    @mcp.tool()
    async def m365_list_service_health(actor: str, reason: str, limit: int = 50, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(graph_connector, budget, operation="m365.service_health.list", limit=limit)
        return _response("m365.service_health.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="m365:service-health")

    @mcp.tool()
    async def m365_list_exchange_service_issues(actor: str, reason: str, limit: int = 50, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(graph_connector, budget, operation="m365.exchange_issues.list", limit=limit)
        return _response("m365.exchange_issues.list", actor=actor, reason=reason, correlation_id=correlation_id, output=page, budget=budget, target="m365:exchange-service-issues")

    @mcp.tool()
    async def exchange_m365_diagnostic_bundle(actor: str, reason: str, connector_limit: int = 25, domain_limit: int = 25, issue_limit: int = 25, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        organization = await _page(exchange_connector, budget, operation="exchange.organization.get", limit=1)
        transport = await _page(exchange_connector, budget, operation="exchange.transport_config.get", limit=1)
        health = await _page(graph_connector, budget, operation="m365.service_health.list", limit=min(50, settings.graph_max_page_size))
        issues = await _page(graph_connector, budget, operation="m365.exchange_issues.list", limit=min(issue_limit, settings.graph_max_page_size))
        inbound = await _page(exchange_connector, budget, operation="exchange.inbound_connectors.list", limit=min(connector_limit, settings.exchange_max_page_size))
        outbound = await _page(exchange_connector, budget, operation="exchange.outbound_connectors.list", limit=min(connector_limit, settings.exchange_max_page_size))
        accepted = await _page(exchange_connector, budget, operation="exchange.accepted_domains.list", limit=min(domain_limit, settings.exchange_max_page_size))
        remote = await _page(exchange_connector, budget, operation="exchange.remote_domains.list", limit=min(domain_limit, settings.exchange_max_page_size))
        output = {"organization": organization, "transportConfig": transport, "serviceHealth": health, "exchangeServiceIssues": issues, "inboundConnectors": inbound, "outboundConnectors": outbound, "acceptedDomains": accepted, "remoteDomains": remote}
        return _response("exchange-m365.diagnostics.bundle", actor=actor, reason=reason, correlation_id=correlation_id, output=output, budget=budget)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
