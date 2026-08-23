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

from .client import GraphReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .endpoints import EntraEndpoint

_CONNECTOR_OPERATIONS = frozenset(f"entra.{endpoint.value}" for endpoint in EntraEndpoint)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="entra.graph.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.entra_max_page_size,
        max_sample_size=settings.entra_max_sample_size,
        request_timeout_seconds=settings.entra_request_timeout_seconds,
        max_response_bytes=settings.entra_max_response_bytes,
        max_concurrency=settings.entra_max_concurrency,
        rate_limit_per_second=settings.entra_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.entra_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.entra_budget_max_requests,
        max_items=settings.entra_budget_max_items,
        max_response_bytes=settings.entra_budget_max_response_bytes,
        max_fan_out=settings.entra_budget_max_fan_out,
        total_timeout_seconds=settings.entra_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="entra-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="entra-mcp")


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
        target="entra:tenant",
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
    cursor: str | None,
    sample_size: int | None,
    sample_strategy: Literal["head", "even"] = "even",
) -> dict[str, Any]:
    sample = SampleRequest(size=sample_size, strategy=sample_strategy) if sample_size is not None else None
    result = await connector.execute(
        ReadOnlyQuery(
            operation=operation,
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


def create_server(settings: Settings | None = None, connector: ReadOnlyConnector | None = None) -> FastMCP:
    settings = settings or Settings()
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(policy, GraphReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-entra",))
    mcp = FastMCP(
        "Flowoox Microsoft Entra Diagnostics MCP",
        instructions=(
            "Bounded read-only Microsoft Entra diagnostics through fixed Microsoft Graph GET "
            "endpoints and app-only credentials. No arbitrary Graph path, OData expression, "
            "delegated user context, raw Graph payload, or write tool is exposed."
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
        return capabilities(connector.policy, budget_limits, cloud=settings.entra_cloud)

    async def list_tool(
        tool_operation: str,
        connector_operation: str,
        *,
        actor: str,
        reason: str,
        limit: int,
        cursor: str,
        sample_size: int | None,
        sample_strategy: Literal["head", "even"],
        correlation_id: str,
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation=connector_operation,
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            tool_operation,
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def entra_observe_tenant(actor: str, reason: str, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="entra.organization.inventory",
            limit=10,
            cursor=None,
            sample_size=None,
        )
        return _response(
            "entra.tenant.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"organizations": page},
            budget=budget,
        )

    @mcp.tool()
    async def entra_list_users(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.users.list", "entra.user.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_groups(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.groups.list", "entra.group.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_devices(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.devices.list", "entra.device.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_applications(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.applications.list", "entra.application.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_service_principals(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.service-principals.list", "entra.service-principal.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_directory_roles(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.directory-roles.list", "entra.directory-role.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_list_conditional_access_policies(actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_tool("entra.conditional-access.list", "entra.conditional-access.policy.inventory", actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def entra_diagnostic_bundle(actor: str, reason: str, item_limit: int = 25, sample_size: int | None = 10, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        sections: dict[str, Any] = {}
        for name, operation in (
            ("organizations", "entra.organization.inventory"),
            ("users", "entra.user.inventory"),
            ("groups", "entra.group.inventory"),
            ("devices", "entra.device.inventory"),
            ("applications", "entra.application.inventory"),
            ("servicePrincipals", "entra.service-principal.inventory"),
            ("directoryRoles", "entra.directory-role.inventory"),
            ("conditionalAccessPolicies", "entra.conditional-access.policy.inventory"),
        ):
            sections[name] = await _page(
                connector,
                budget,
                operation=operation,
                limit=item_limit,
                cursor=None,
                sample_size=sample_size,
            )
        return _response(
            "entra.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=sections,
            budget=budget,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
