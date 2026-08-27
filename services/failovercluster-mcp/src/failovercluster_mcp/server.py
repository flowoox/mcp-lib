from __future__ import annotations

from typing import Any
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
    ReadOnlyPage,
    ReadOnlyQuery,
)

from .config import Settings
from .contract import capabilities
from .transport import FailoverClusterReadOnlyTransport

_BACKEND_OPERATIONS = frozenset(
    {
        "failovercluster.cluster.observe",
        "failovercluster.node.list",
        "failovercluster.group.list",
        "failovercluster.group.observe",
        "failovercluster.resource.list",
        "failovercluster.network.list",
        "failovercluster.storage.list",
        "failovercluster.quorum.observe",
        "failovercluster.event.list",
    }
)


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.failovercluster_budget_max_requests,
        max_items=settings.failovercluster_budget_max_items,
        max_response_bytes=settings.failovercluster_budget_max_response_bytes,
        max_fan_out=settings.failovercluster_budget_max_fan_out,
        total_timeout_seconds=settings.failovercluster_budget_timeout_seconds,
    )


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="failovercluster-powershell",
        allowed_operations=_BACKEND_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.failovercluster_max_page_size,
        max_sample_size=settings.failovercluster_max_sample_size,
        request_timeout_seconds=settings.failovercluster_request_timeout_seconds,
        max_response_bytes=settings.failovercluster_max_response_bytes,
        max_concurrency=settings.failovercluster_max_concurrency,
        rate_limit_per_second=settings.failovercluster_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.failovercluster_cache_max_age_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="failovercluster-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="failovercluster-mcp")


def _reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return value


def _response(
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


async def _query(
    connector: ReadOnlyConnector,
    budget: QueryBudget,
    operation: str,
    *,
    target_id: str,
    limit: int,
    cursor: str = "",
    parameters: dict[str, Any] | None = None,
) -> ReadOnlyPage:
    query_parameters = {"target_id": target_id}
    query_parameters.update(parameters or {})
    return await connector.execute(
        ReadOnlyQuery(
            operation=operation,
            parameters=query_parameters,
            page=PageRequest(limit=limit, cursor=cursor or None),
            aggregated=True,
        ),
        budget,
    )


def _page(page: ReadOnlyPage) -> dict[str, Any]:
    return {
        "items": page.items,
        "nextCursor": page.next_cursor,
        "truncated": page.truncated,
        "sampled": page.sampled,
        "cacheHint": None
        if page.cache_hint is None
        else page.cache_hint.model_dump(mode="json"),
    }


def create_server(
    settings: Settings | None = None,
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    budget_limits = _budget_limits(settings)
    connector_policy = _connector_policy(settings)
    if connector is None:
        transport = FailoverClusterReadOnlyTransport(settings)
        connector = ReadOnlyConnector(connector_policy, transport)

    security = build_mcp_server_security(settings, service_hosts=("mcp-failovercluster",))
    mcp = FastMCP(
        "Flowoox Failover Cluster Diagnostics MCP",
        instructions=(
            "Bounded read-only Windows Failover Cluster diagnostics over configured target aliases. "
            "The production default requires constrained JEA/WinRM endpoints. No arbitrary "
            "PowerShell/CIM/WMI, cluster state mutation, role/resource movement, quorum changes, "
            "storage mutation or network mutation is exposed."
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
            budget_limits,
            connector_policy,
            require_jea=settings.failovercluster_require_jea,
        )

    @mcp.tool()
    async def failovercluster_observe_cluster(
        actor: str,
        reason: str,
        target_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "failovercluster.cluster.observe",
            target_id=target_id,
            limit=1,
        )
        return _response(
            "failovercluster.cluster.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"cluster": page.items[0] if page.items else None},
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def failovercluster_list_nodes(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "failovercluster.node.list", target_id=target_id, limit=limit, cursor=cursor)
        return _response("failovercluster.node.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=target_id)

    @mcp.tool()
    async def failovercluster_list_groups(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "failovercluster.group.list", target_id=target_id, limit=limit, cursor=cursor)
        return _response("failovercluster.group.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=target_id)

    @mcp.tool()
    async def failovercluster_observe_group(
        actor: str,
        reason: str,
        target_id: str,
        group_name: str,
        resource_limit: int = 32,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "failovercluster.group.observe",
            target_id=target_id,
            limit=1,
            parameters={"group_name": group_name, "resource_limit": resource_limit},
        )
        return _response(
            "failovercluster.group.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"group": page.items[0] if page.items else None},
            budget=budget,
            target=f"{target_id}:{group_name}",
        )

    @mcp.tool()
    async def failovercluster_list_resources(
        actor: str,
        reason: str,
        target_id: str,
        group_name: str = "",
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "failovercluster.resource.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
            parameters={"group_name": group_name or None},
        )
        target = f"{target_id}:{group_name}" if group_name else target_id
        return _response("failovercluster.resource.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=target)

    @mcp.tool()
    async def failovercluster_list_networks(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "failovercluster.network.list", target_id=target_id, limit=limit, cursor=cursor)
        return _response("failovercluster.network.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=target_id)

    @mcp.tool()
    async def failovercluster_list_storage(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "failovercluster.storage.list", target_id=target_id, limit=limit, cursor=cursor)
        return _response("failovercluster.storage.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=target_id)

    @mcp.tool()
    async def failovercluster_observe_quorum(
        actor: str,
        reason: str,
        target_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "failovercluster.quorum.observe", target_id=target_id, limit=1)
        return _response("failovercluster.quorum.observe", actor=actor, reason=reason, correlation_id=correlation_id, output={"quorum": page.items[0] if page.items else None}, budget=budget, target=target_id)

    @mcp.tool()
    async def failovercluster_list_events(
        actor: str,
        reason: str,
        target_id: str,
        lookback_minutes: int = 60,
        level: str = "error",
        include_message: bool = False,
        limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "failovercluster.event.list",
            target_id=target_id,
            limit=limit,
            parameters={"lookback_minutes": lookback_minutes, "level": level, "include_message": include_message},
        )
        return _response("failovercluster.event.list", actor=actor, reason=reason, correlation_id=correlation_id, output=_page(page), budget=budget, target=f"{target_id}:cluster-operational")

    @mcp.tool()
    async def failovercluster_diagnose_cluster(
        actor: str,
        reason: str,
        target_id: str,
        max_nodes: int = 32,
        max_groups: int = 64,
        max_storage: int = 32,
        max_events: int = 25,
        lookback_minutes: int = 60,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)

        # Aggregate-first: collect one bounded cluster summary before any relationship detail.
        cluster_page = await _query(connector, budget, "failovercluster.cluster.observe", target_id=target_id, limit=1)
        if not cluster_page.items:
            raise ValueError("cluster was not found on the configured target")
        nodes = await _query(connector, budget, "failovercluster.node.list", target_id=target_id, limit=max_nodes)
        groups = await _query(connector, budget, "failovercluster.group.list", target_id=target_id, limit=max_groups)
        storage = await _query(connector, budget, "failovercluster.storage.list", target_id=target_id, limit=max_storage)
        quorum = await _query(connector, budget, "failovercluster.quorum.observe", target_id=target_id, limit=1)
        events = await _query(
            connector,
            budget,
            "failovercluster.event.list",
            target_id=target_id,
            limit=max_events,
            parameters={"lookback_minutes": lookback_minutes, "level": "error", "include_message": False},
        )
        return _response(
            "failovercluster.cluster.diagnose",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "cluster": cluster_page.items[0],
                "relationships": {
                    "nodes": nodes.items,
                    "groups": groups.items,
                    "storage": storage.items,
                    "quorum": quorum.items[0] if quorum.items else None,
                    "recentErrors": events.items,
                },
                "truncated": {
                    "nodes": nodes.truncated,
                    "groups": groups.truncated,
                    "storage": storage.truncated,
                    "recentErrors": events.truncated,
                },
            },
            budget=budget,
            target=target_id,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
