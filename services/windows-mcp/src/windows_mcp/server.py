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
from .transport import WindowsReadOnlyTransport

_CONNECTOR_OPERATIONS = frozenset(
    {
        "windows.host.inventory",
        "windows.service.inventory",
        "windows.process.inventory",
        "windows.feature.inventory",
        "windows.event.inventory",
        "windows.certificate.inventory",
        "windows.update.inventory",
        "windows.hyperv.host.inventory",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="windows.powershell.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.windows_max_page_size,
        max_sample_size=settings.windows_max_sample_size,
        request_timeout_seconds=settings.windows_request_timeout_seconds,
        max_response_bytes=settings.windows_max_response_bytes,
        max_concurrency=settings.windows_max_concurrency,
        rate_limit_per_second=settings.windows_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.windows_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.windows_budget_max_requests,
        max_items=settings.windows_budget_max_items,
        max_response_bytes=settings.windows_budget_max_response_bytes,
        max_fan_out=settings.windows_budget_max_fan_out,
        total_timeout_seconds=settings.windows_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="windows-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="windows-mcp")


def _reason(value: str) -> str:
    normalized = value.strip()
    if not 1 <= len(normalized) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return normalized


def _response(
    operation: str,
    *,
    target_id: str,
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
        target=f"windows:{target_id}",
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
    target_id: str,
    parameters: dict[str, Any] | None,
    limit: int,
    cursor: str | None,
    sample_size: int | None,
    sample_strategy: Literal["head", "even"] = "even",
) -> dict[str, Any]:
    sample = SampleRequest(size=sample_size, strategy=sample_strategy) if sample_size is not None else None
    merged = {"target_id": target_id, **(parameters or {})}
    result = await connector.execute(
        ReadOnlyQuery(
            operation=operation,
            parameters=merged,
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
    targets = settings.targets
    event_logs = settings.allowed_event_logs
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(policy, WindowsReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-windows",))
    mcp = FastMCP(
        "Flowoox Windows Server Diagnostics MCP",
        instructions=(
            "Bounded read-only Windows Server diagnostics using repository-owned PowerShell probes "
            "and configured local/JEA WinRM targets. No arbitrary command, PowerShell, cmdlet, event "
            "log, certificate path, raw process output, or write tool is exposed."
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
            target_ids=list(targets),
            allowed_event_logs=list(event_logs),
            remote_requires_jea=settings.windows_require_jea,
        )

    async def one_page(
        tool_operation: str,
        connector_operation: str,
        *,
        target_id: str,
        actor: str,
        reason: str,
        parameters: dict[str, Any] | None = None,
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
            operation=connector_operation,
            target_id=target_id,
            parameters=parameters,
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            tool_operation,
            target_id=target_id,
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def windows_observe_host(target_id: str, actor: str, reason: str, correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.host.observe", "windows.host.inventory", target_id=target_id, actor=actor, reason=reason, limit=1, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_list_services(target_id: str, actor: str, reason: str, state: Literal["all", "running", "stopped"] = "all", limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.services.list", "windows.service.inventory", target_id=target_id, actor=actor, reason=reason, parameters={"state": state}, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_list_processes(
        target_id: str,
        actor: str,
        reason: str,
        sort_by: Literal["working_set", "cpu", "name"] = "working_set",
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        return await one_page(
            "windows.processes.list",
            "windows.process.inventory",
            target_id=target_id,
            actor=actor,
            reason=reason,
            parameters={"sort_by": sort_by},
            limit=limit,
            cursor=cursor,
            sample_size=sample_size,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def windows_list_features(target_id: str, actor: str, reason: str, installed_only: bool = True, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.features.list", "windows.feature.inventory", target_id=target_id, actor=actor, reason=reason, parameters={"installed_only": installed_only}, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_list_events(target_id: str, actor: str, reason: str, log_name: str = "System", lookback_minutes: int = 60, level: Literal["all", "critical", "error", "warning"] = "error", include_message: bool = False, limit: int = 50, sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.events.list", "windows.event.inventory", target_id=target_id, actor=actor, reason=reason, parameters={"log_name": log_name, "lookback_minutes": lookback_minutes, "level": level, "include_message": include_message}, limit=limit, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_list_certificates(target_id: str, actor: str, reason: str, store_id: Literal["machine-my", "machine-root", "machine-ca"] = "machine-my", expiring_within_days: int | None = None, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.certificates.list", "windows.certificate.inventory", target_id=target_id, actor=actor, reason=reason, parameters={"store_id": store_id, "expiring_within_days": expiring_within_days}, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_list_updates(target_id: str, actor: str, reason: str, limit: int = 50, cursor: str = "", sample_size: int | None = None, sample_strategy: Literal["head", "even"] = "even", correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.updates.list", "windows.update.inventory", target_id=target_id, actor=actor, reason=reason, limit=limit, cursor=cursor, sample_size=sample_size, sample_strategy=sample_strategy, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_observe_hyperv_host(target_id: str, actor: str, reason: str, correlation_id: str = "") -> dict[str, Any]:
        return await one_page("windows.hyperv-host.observe", "windows.hyperv.host.inventory", target_id=target_id, actor=actor, reason=reason, limit=1, correlation_id=correlation_id)

    @mcp.tool()
    async def windows_diagnostic_bundle(target_id: str, actor: str, reason: str, event_log: str = "System", event_lookback_minutes: int = 60, correlation_id: str = "") -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        sections: dict[str, Any] = {}
        sections["host"] = await _page(connector, budget, operation="windows.host.inventory", target_id=target_id, parameters=None, limit=1, cursor=None, sample_size=None)
        sections["services"] = await _page(connector, budget, operation="windows.service.inventory", target_id=target_id, parameters={"state": "all"}, limit=25, cursor=None, sample_size=10)
        sections["processes"] = await _page(connector, budget, operation="windows.process.inventory", target_id=target_id, parameters={"sort_by": "working_set"}, limit=25, cursor=None, sample_size=10)
        sections["features"] = await _page(connector, budget, operation="windows.feature.inventory", target_id=target_id, parameters={"installed_only": True}, limit=25, cursor=None, sample_size=10)
        sections["events"] = await _page(connector, budget, operation="windows.event.inventory", target_id=target_id, parameters={"log_name": event_log, "lookback_minutes": event_lookback_minutes, "level": "error", "include_message": False}, limit=25, cursor=None, sample_size=10)
        sections["certificates"] = await _page(connector, budget, operation="windows.certificate.inventory", target_id=target_id, parameters={"store_id": "machine-my", "expiring_within_days": 60}, limit=25, cursor=None, sample_size=10)
        sections["updates"] = await _page(connector, budget, operation="windows.update.inventory", target_id=target_id, parameters=None, limit=25, cursor=None, sample_size=10)
        sections["hyperv"] = await _page(connector, budget, operation="windows.hyperv.host.inventory", target_id=target_id, parameters=None, limit=1, cursor=None, sample_size=None)
        return _response("windows.diagnostics.bundle", target_id=target_id, actor=actor, reason=reason, correlation_id=correlation_id, output=sections, budget=budget)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
