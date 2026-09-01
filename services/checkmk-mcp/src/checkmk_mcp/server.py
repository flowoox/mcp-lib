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

from .client import CheckmkReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import MonitoringProblemSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "checkmk.version.get",
        "checkmk.problem_hosts.list",
        "checkmk.problem_services.list",
        "checkmk.host.problem_services",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="checkmk.rest-1.0.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.checkmk_max_page_size,
        max_sample_size=settings.checkmk_max_sample_size,
        request_timeout_seconds=settings.checkmk_request_timeout_seconds,
        max_response_bytes=settings.checkmk_max_response_bytes,
        max_concurrency=settings.checkmk_max_concurrency,
        rate_limit_per_second=settings.checkmk_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.checkmk_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.checkmk_budget_max_requests,
        max_items=settings.checkmk_budget_max_items,
        max_response_bytes=settings.checkmk_budget_max_response_bytes,
        max_fan_out=settings.checkmk_budget_max_fan_out,
        total_timeout_seconds=settings.checkmk_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="checkmk-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="checkmk-mcp")


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
    target: str = "checkmk:monitoring",
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
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(
        policy,
        CheckmkReadOnlyTransport(settings),
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-checkmk",))
    mcp = FastMCP(
        "Flowoox Checkmk Diagnostics MCP",
        instructions=(
            "Bounded read-only Checkmk monitoring diagnostics through the stable REST 1.0 API. "
            "Only fixed problem-host/service queries and version observation are exposed. "
            "Addresses, contacts, plugin output, performance data, comments, arbitrary Livestatus "
            "queries, configuration endpoints and state-changing actions are not exposed."
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
            connector.policy,
            budget_limits,
            backend_role=settings.checkmk_backend_role,
        )

    @mcp.tool()
    async def checkmk_get_version(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="checkmk.version.get",
            limit=1,
        )
        return _response(
            "checkmk.version.get",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="checkmk:version",
        )

    @mcp.tool()
    async def checkmk_list_problem_hosts(
        actor: str,
        reason: str,
        limit: int = 50,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="checkmk.problem_hosts.list",
            limit=limit,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "checkmk.problem_hosts.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="checkmk:problem-hosts",
        )

    @mcp.tool()
    async def checkmk_list_problem_services(
        actor: str,
        reason: str,
        limit: int = 50,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="checkmk.problem_services.list",
            limit=limit,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "checkmk.problem_services.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="checkmk:problem-services",
        )

    @mcp.tool()
    async def checkmk_list_host_problem_services(
        actor: str,
        reason: str,
        host_name: str,
        limit: int = 50,
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="checkmk.host.problem_services",
            limit=limit,
            parameters={"host_name": host_name},
            sample_size=sample_size,
        )
        return _response(
            "checkmk.host.problem_services",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"checkmk:host:{host_name}",
        )

    @mcp.tool()
    async def checkmk_diagnostic_bundle(
        actor: str,
        reason: str,
        problem_limit: int = 25,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        version = await _page(
            connector,
            budget,
            operation="checkmk.version.get",
            limit=1,
        )
        problem_hosts = await _page(
            connector,
            budget,
            operation="checkmk.problem_hosts.list",
            limit=min(problem_limit, settings.checkmk_max_page_size),
        )
        problem_services = await _page(
            connector,
            budget,
            operation="checkmk.problem_services.list",
            limit=min(problem_limit, settings.checkmk_max_page_size),
        )
        summary = MonitoringProblemSummary(
            problem_hosts_returned=problem_hosts["returned"],
            problem_hosts_truncated=problem_hosts["truncated"],
            problem_services_returned=problem_services["returned"],
            problem_services_truncated=problem_services["truncated"],
        ).model_dump(mode="json")
        output = {
            "version": version,
            "problemHosts": problem_hosts,
            "problemServices": problem_services,
            "summary": summary,
            "countSemantics": (
                "returned counts are exact only when truncated=false; otherwise they are bounded "
                "lower bounds for this diagnostic request"
            ),
        }
        return _response(
            "checkmk.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=output,
            budget=budget,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
