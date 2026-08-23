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

from .client import FortiGateApiTransport
from .config import Settings
from .contract import capabilities
from .endpoints import FortiGateEndpoint

_CONNECTOR_OPERATIONS = frozenset(f"fortigate.{endpoint.value}" for endpoint in FortiGateEndpoint)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="fortigate.rest.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.fortigate_max_page_size,
        max_sample_size=settings.fortigate_max_sample_size,
        request_timeout_seconds=settings.fortigate_request_timeout_seconds,
        max_response_bytes=settings.fortigate_max_response_bytes,
        max_concurrency=settings.fortigate_max_concurrency,
        rate_limit_per_second=settings.fortigate_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.fortigate_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.fortigate_budget_max_requests,
        max_items=settings.fortigate_budget_max_items,
        max_response_bytes=settings.fortigate_budget_max_response_bytes,
        max_fan_out=settings.fortigate_budget_max_fan_out,
        total_timeout_seconds=settings.fortigate_budget_timeout_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="fortigate-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="fortigate-mcp")


def _reason(value: str) -> str:
    normalized = value.strip()
    if not 1 <= len(normalized) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return normalized


def _observe_response(
    operation: str,
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    output: dict[str, Any],
    budget: QueryBudget,
    target: str,
) -> dict[str, Any]:
    context = _operation_context(actor, correlation_id)
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


def _one(items: list[Any], operation: str) -> dict[str, Any]:
    if len(items) != 1 or not isinstance(items[0], dict):
        raise RuntimeError(f"{operation} returned an invalid normalized result")
    return items[0]


async def _list_page(
    connector: ReadOnlyConnector,
    budget: QueryBudget,
    *,
    operation: str,
    vdom: str,
    limit: int,
    cursor: str | None,
    sample_size: int | None,
    sample_strategy: Literal["head", "even"] = "even",
    aggregated: bool = True,
) -> dict[str, Any]:
    sample = SampleRequest(size=sample_size, strategy=sample_strategy) if sample_size is not None else None
    page = await connector.execute(
        ReadOnlyQuery(
            operation=operation,
            parameters={"vdom": vdom},
            page=PageRequest(limit=limit, cursor=cursor),
            sample=sample,
            aggregated=aggregated,
        ),
        budget,
    )
    return {
        "items": page.items,
        "returned": len(page.items),
        "nextCursor": page.next_cursor,
        "truncated": page.truncated,
        "sampled": page.sampled,
        "cacheHint": page.cache_hint.model_dump(mode="json") if page.cache_hint else None,
    }


def create_server(settings: Settings | None = None, connector: ReadOnlyConnector | None = None) -> FastMCP:
    settings = settings or Settings()
    connector_policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(connector_policy, FortiGateApiTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-fortigate",))
    mcp = FastMCP(
        "Flowoox FortiGate Diagnostics MCP",
        instructions=(
            "Bounded read-only FortiGate diagnostics using fixed GET endpoints, allowlisted VDOMs, "
            "backend field projection and query budgets. No arbitrary API path, filter, method, raw "
            "configuration payload or write tool is exposed."
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
        return capabilities(connector.policy, budget_limits)

    @mcp.tool()
    async def fortigate_observe_system(actor: str, reason: str, vdom: str = "", correlation_id: str = "") -> dict[str, Any]:
        selected_vdom = settings.resolve_vdom(vdom or None)
        budget = QueryBudget(budget_limits)
        status = await connector.execute(
            ReadOnlyQuery(
                operation="fortigate.system.status",
                parameters={"vdom": selected_vdom},
                page=PageRequest(limit=1),
            ),
            budget,
        )
        ha = await connector.execute(
            ReadOnlyQuery(operation="fortigate.ha.configuration", page=PageRequest(limit=1)),
            budget,
        )
        return _observe_response(
            "fortigate.system.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"vdom": selected_vdom, "system": _one(status.items, "system.status"), "ha": _one(ha.items, "ha.configuration")},
            budget=budget,
            target=f"fortigate:vdom:{selected_vdom}",
        )

    async def list_observation(
        tool_operation: str,
        connector_operation: str,
        *,
        actor: str,
        reason: str,
        vdom: str,
        limit: int,
        cursor: str,
        sample_size: int | None,
        sample_strategy: Literal["head", "even"],
        correlation_id: str,
    ) -> dict[str, Any]:
        selected_vdom = settings.resolve_vdom(vdom or None)
        budget = QueryBudget(budget_limits)
        page = await _list_page(
            connector,
            budget,
            operation=connector_operation,
            vdom=selected_vdom,
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _observe_response(
            tool_operation,
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"vdom": selected_vdom, **page},
            budget=budget,
            target=f"fortigate:vdom:{selected_vdom}",
        )

    @mcp.tool()
    async def fortigate_list_interfaces(actor: str, reason: str, vdom: str = "", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_observation("fortigate.interfaces.list", "fortigate.interface.inventory", actor=actor, reason=reason, vdom=vdom, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def fortigate_list_static_routes(actor: str, reason: str, vdom: str = "", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_observation("fortigate.routes.list", "fortigate.route.static", actor=actor, reason=reason, vdom=vdom, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def fortigate_list_firewall_policies(actor: str, reason: str, vdom: str = "", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_observation("fortigate.policies.list", "fortigate.policy.inventory", actor=actor, reason=reason, vdom=vdom, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def fortigate_list_firewall_addresses(actor: str, reason: str, vdom: str = "", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_observation("fortigate.addresses.list", "fortigate.address.inventory", actor=actor, reason=reason, vdom=vdom, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def fortigate_list_ipsec_phase1(actor: str, reason: str, vdom: str = "", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await list_observation("fortigate.ipsec.list", "fortigate.vpn.ipsec.phase1", actor=actor, reason=reason, vdom=vdom, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def fortigate_diagnostic_bundle(actor: str, reason: str, vdom: str = "", item_limit: int = 25, sample_size: int | None = 10, correlation_id: str = "") -> dict[str, Any]:
        selected_vdom = settings.resolve_vdom(vdom or None)
        budget = QueryBudget(budget_limits)
        status = await connector.execute(ReadOnlyQuery(operation="fortigate.system.status", parameters={"vdom": selected_vdom}, page=PageRequest(limit=1)), budget)
        ha = await connector.execute(ReadOnlyQuery(operation="fortigate.ha.configuration", page=PageRequest(limit=1)), budget)
        sections: dict[str, Any] = {}
        for name, operation in (
            ("interfaces", "fortigate.interface.inventory"),
            ("routes", "fortigate.route.static"),
            ("policies", "fortigate.policy.inventory"),
            ("ipsecPhase1", "fortigate.vpn.ipsec.phase1"),
        ):
            sections[name] = await _list_page(
                connector,
                budget,
                operation=operation,
                vdom=selected_vdom,
                limit=item_limit,
                cursor=None,
                sample_size=sample_size,
                aggregated=True,
            )
        return _observe_response(
            "fortigate.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "vdom": selected_vdom,
                "system": _one(status.items, "system.status"),
                "ha": _one(ha.items, "ha.configuration"),
                **sections,
            },
            budget=budget,
            target=f"fortigate:vdom:{selected_vdom}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
