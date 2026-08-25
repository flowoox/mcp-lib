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

from .client import PrtgReadOnlyTransport
from .config import Settings
from .contract import capabilities

_CONNECTOR_OPERATIONS = frozenset(
    {
        "prtg.system.health-status",
        "prtg.system.health-data",
        "prtg.devices.list",
        "prtg.sensors.list",
        "prtg.alarms.list",
        "prtg.channels.list",
        "prtg.messages.list",
        "prtg.historic.sensor",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="prtg.http.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.prtg_max_page_size,
        max_sample_size=settings.prtg_max_sample_size,
        request_timeout_seconds=settings.prtg_request_timeout_seconds,
        max_response_bytes=settings.prtg_max_response_bytes,
        max_concurrency=settings.prtg_max_concurrency,
        rate_limit_per_second=settings.prtg_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.prtg_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.prtg_budget_max_requests,
        max_items=settings.prtg_budget_max_items,
        max_response_bytes=settings.prtg_budget_max_response_bytes,
        max_fan_out=settings.prtg_budget_max_fan_out,
        total_timeout_seconds=settings.prtg_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="prtg-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="prtg-mcp")


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
    target: str = "prtg:monitoring",
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
    sample = SampleRequest(size=sample_size, strategy=sample_strategy) if sample_size is not None else None
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
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(policy, PrtgReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-prtg",))
    mcp = FastMCP(
        "Flowoox PRTG Diagnostics MCP",
        instructions=(
            "Bounded read-only PRTG diagnostics through fixed documented HTTP API GET operations. "
            "The service never exposes an arbitrary URL, HTTP method, table column, filter, refresh-now "
            "request, credential value, or write operation. Historic data is separately rate-limited."
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
            historic_max_window_hours=settings.prtg_historic_max_window_hours,
        )

    async def list_tool(
        tool_operation: str,
        connector_operation: str,
        *,
        actor: str,
        reason: str,
        limit: int,
        cursor: str,
        object_id: int | None,
        sample_size: int | None,
        sample_strategy: Literal["head", "even"],
        correlation_id: str,
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters = {"object_id": object_id} if object_id is not None else {}
        page = await _page(
            connector,
            budget,
            operation=connector_operation,
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
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
    async def prtg_health_status(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="prtg.system.health-status",
            limit=1,
        )
        return _response(
            "prtg.health-status.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def prtg_health_data(
        actor: str,
        reason: str,
        maxage_seconds: int = 120,
        limit: int = 64,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="prtg.system.health-data",
            limit=limit,
            parameters={"maxage_seconds": maxage_seconds},
        )
        return _response(
            "prtg.health-data.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def prtg_list_devices(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        object_id: int | None = None,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return await list_tool(
            "prtg.devices.list",
            "prtg.devices.list",
            actor=actor,
            reason=reason,
            limit=limit,
            cursor=cursor,
            object_id=object_id,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def prtg_list_sensors(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        object_id: int | None = None,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return await list_tool(
            "prtg.sensors.list",
            "prtg.sensors.list",
            actor=actor,
            reason=reason,
            limit=limit,
            cursor=cursor,
            object_id=object_id,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def prtg_list_alarms(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        object_id: int | None = None,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return await list_tool(
            "prtg.alarms.list",
            "prtg.alarms.list",
            actor=actor,
            reason=reason,
            limit=limit,
            cursor=cursor,
            object_id=object_id,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def prtg_list_channels(
        actor: str,
        reason: str,
        sensor_id: int,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="prtg.channels.list",
            limit=limit,
            cursor=cursor or None,
            parameters={"sensor_id": sensor_id},
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "prtg.channels.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"prtg:sensor:{sensor_id}",
        )

    @mcp.tool()
    async def prtg_list_messages(
        actor: str,
        reason: str,
        window: Literal["today", "yesterday", "7days"] = "today",
        limit: int = 50,
        cursor: str = "",
        object_id: int | None = None,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters: dict[str, Any] = {"window": window}
        if object_id is not None:
            parameters["object_id"] = object_id
        page = await _page(
            connector,
            budget,
            operation="prtg.messages.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "prtg.messages.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def prtg_get_historic_data(
        actor: str,
        reason: str,
        sensor_id: int,
        start: str,
        end: str,
        average_seconds: int = 0,
        limit: int = 100,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="prtg.historic.sensor",
            limit=limit,
            parameters={
                "sensor_id": sensor_id,
                "start": start,
                "end": end,
                "average_seconds": average_seconds,
            },
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "prtg.historic.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"prtg:sensor:{sensor_id}",
        )

    @mcp.tool()
    async def prtg_diagnostic_bundle(
        actor: str,
        reason: str,
        item_limit: int = 25,
        object_id: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        scope = {"object_id": object_id} if object_id is not None else {}
        sections = {
            "healthStatus": await _page(
                connector,
                budget,
                operation="prtg.system.health-status",
                limit=1,
            ),
            "healthData": await _page(
                connector,
                budget,
                operation="prtg.system.health-data",
                limit=min(64, settings.prtg_max_page_size),
                parameters={"maxage_seconds": settings.prtg_health_max_age_seconds},
            ),
            "alarms": await _page(
                connector,
                budget,
                operation="prtg.alarms.list",
                limit=item_limit,
                parameters=scope,
            ),
            "devices": await _page(
                connector,
                budget,
                operation="prtg.devices.list",
                limit=item_limit,
                parameters=scope,
                sample_size=min(item_limit, 10),
            ),
            "sensors": await _page(
                connector,
                budget,
                operation="prtg.sensors.list",
                limit=item_limit,
                parameters=scope,
                sample_size=min(item_limit, 10),
            ),
        }
        return _response(
            "prtg.diagnostics.bundle",
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
