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
from .transport import HyperVReadOnlyTransport

_BACKEND_OPERATIONS = frozenset(
    {
        "hyperv.host.observe",
        "hyperv.vm.list",
        "hyperv.vm.observe",
        "hyperv.switch.list",
        "hyperv.checkpoint.list",
        "hyperv.vhd.list",
        "hyperv.replication.list",
        "hyperv.event.list",
    }
)


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.hyperv_budget_max_requests,
        max_items=settings.hyperv_budget_max_items,
        max_response_bytes=settings.hyperv_budget_max_response_bytes,
        max_fan_out=settings.hyperv_budget_max_fan_out,
        total_timeout_seconds=settings.hyperv_budget_timeout_seconds,
    )


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="hyperv-powershell",
        allowed_operations=_BACKEND_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.hyperv_max_page_size,
        max_sample_size=settings.hyperv_max_sample_size,
        request_timeout_seconds=settings.hyperv_request_timeout_seconds,
        max_response_bytes=settings.hyperv_max_response_bytes,
        max_concurrency=settings.hyperv_max_concurrency,
        rate_limit_per_second=settings.hyperv_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.hyperv_cache_max_age_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="hyperv-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="hyperv-mcp")


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
        transport = HyperVReadOnlyTransport(settings)
        connector = ReadOnlyConnector(connector_policy, transport)

    security = build_mcp_server_security(settings, service_hosts=("mcp-hyperv",))
    mcp = FastMCP(
        "Flowoox Hyper-V Diagnostics MCP",
        instructions=(
            "Bounded read-only Hyper-V diagnostics over configured target aliases. "
            "The production default requires constrained JEA/WinRM endpoints. "
            "No arbitrary PowerShell/CIM/WMI, guest command, VM state change, checkpoint change, "
            "storage mutation or networking mutation is exposed."
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
            require_jea=settings.hyperv_require_jea,
        )

    @mcp.tool()
    async def hyperv_observe_host(
        actor: str,
        reason: str,
        target_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.host.observe",
            target_id=target_id,
            limit=1,
        )
        return _response(
            "hyperv.host.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"host": page.items[0] if page.items else None},
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def hyperv_list_vms(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 100,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.vm.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
        )
        return _response(
            "hyperv.vm.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def hyperv_observe_vm(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.vm.observe",
            target_id=target_id,
            limit=1,
            parameters={"vm_name": vm_name},
        )
        return _response(
            "hyperv.vm.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"vm": page.items[0] if page.items else None},
            budget=budget,
            target=f"{target_id}:{vm_name}",
        )

    @mcp.tool()
    async def hyperv_list_switches(
        actor: str,
        reason: str,
        target_id: str,
        limit: int = 50,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.switch.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
        )
        return _response(
            "hyperv.switch.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def hyperv_list_checkpoints(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        limit: int = 50,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.checkpoint.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
            parameters={"vm_name": vm_name},
        )
        return _response(
            "hyperv.checkpoint.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=f"{target_id}:{vm_name}",
        )

    @mcp.tool()
    async def hyperv_list_vhds(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        limit: int = 16,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.vhd.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
            parameters={"vm_name": vm_name},
        )
        return _response(
            "hyperv.vhd.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=f"{target_id}:{vm_name}",
        )

    @mcp.tool()
    async def hyperv_list_replication(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str = "",
        limit: int = 50,
        cursor: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "hyperv.replication.list",
            target_id=target_id,
            limit=limit,
            cursor=cursor,
            parameters={"vm_name": vm_name or None},
        )
        return _response(
            "hyperv.replication.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=f"{target_id}:{vm_name}" if vm_name else target_id,
        )

    @mcp.tool()
    async def hyperv_list_events(
        actor: str,
        reason: str,
        target_id: str,
        log_id: str = "vmms",
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
            "hyperv.event.list",
            target_id=target_id,
            limit=limit,
            parameters={
                "log_id": log_id,
                "lookback_minutes": lookback_minutes,
                "level": level,
                "include_message": include_message,
            },
        )
        return _response(
            "hyperv.event.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=f"{target_id}:{log_id}",
        )

    @mcp.tool()
    async def hyperv_diagnose_vm(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        max_checkpoints: int = 20,
        max_vhds: int = 16,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)

        # Aggregate-first: confirm the exact VM and collect its bounded summary before
        # any relationship fan-out.
        vm_page = await _query(
            connector,
            budget,
            "hyperv.vm.observe",
            target_id=target_id,
            limit=1,
            parameters={"vm_name": vm_name},
        )
        if not vm_page.items:
            raise ValueError("VM was not found on the configured target")

        checkpoints = await _query(
            connector,
            budget,
            "hyperv.checkpoint.list",
            target_id=target_id,
            limit=max_checkpoints,
            parameters={"vm_name": vm_name},
        )
        vhds = await _query(
            connector,
            budget,
            "hyperv.vhd.list",
            target_id=target_id,
            limit=max_vhds,
            parameters={"vm_name": vm_name},
        )
        replication = await _query(
            connector,
            budget,
            "hyperv.replication.list",
            target_id=target_id,
            limit=1,
            parameters={"vm_name": vm_name},
        )
        return _response(
            "hyperv.vm.diagnose",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "vm": vm_page.items[0],
                "relationships": {
                    "checkpoints": checkpoints.items,
                    "vhds": vhds.items,
                    "replication": replication.items,
                },
                "truncated": {
                    "checkpoints": checkpoints.truncated,
                    "vhds": vhds.truncated,
                    "replication": replication.truncated,
                },
            },
            budget=budget,
            target=f"{target_id}:{vm_name}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
