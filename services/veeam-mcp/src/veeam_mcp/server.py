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

from .client import VeeamReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import DiagnosticSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "veeam.jobs.states",
        "veeam.sessions.list",
        "veeam.repositories.states",
        "veeam.backups.list",
        "veeam.restore_points.list",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="veeam.vbr13.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.veeam_max_page_size,
        max_sample_size=settings.veeam_max_sample_size,
        request_timeout_seconds=settings.veeam_request_timeout_seconds,
        max_response_bytes=settings.veeam_max_response_bytes,
        max_concurrency=settings.veeam_max_concurrency,
        rate_limit_per_second=settings.veeam_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.veeam_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.veeam_budget_max_requests,
        max_items=settings.veeam_budget_max_items,
        max_response_bytes=settings.veeam_budget_max_response_bytes,
        max_fan_out=settings.veeam_budget_max_fan_out,
        total_timeout_seconds=settings.veeam_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="veeam-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="veeam-mcp")


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
    target: str,
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
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(policy, VeeamReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-veeam",))
    mcp = FastMCP(
        "Flowoox Veeam Backup Diagnostics MCP",
        instructions=(
            "Bounded read-only diagnostics for Veeam Backup & Replication 13 REST API 1.3-rev2. "
            "The backend identity must be the built-in Backup Viewer role. The adapter performs "
            "only the exact OAuth token request needed for authentication and fixed GET observation "
            "routes; job actions, restores, configuration mutations, credential inventory, arbitrary "
            "filters and caller-selected API paths are intentionally absent."
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
            max_offset=settings.veeam_max_offset,
            max_history_hours=settings.veeam_max_history_hours,
        )

    @mcp.tool()
    async def veeam_list_job_states(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="veeam.jobs.states",
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
        )
        return _response(
            "veeam.jobs.states",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="veeam:jobs",
        )

    @mcp.tool()
    async def veeam_list_sessions(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="veeam.sessions.list",
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
        )
        return _response(
            "veeam.sessions.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="veeam:sessions",
        )

    @mcp.tool()
    async def veeam_list_repository_states(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="veeam.repositories.states",
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
        )
        return _response(
            "veeam.repositories.states",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="veeam:repositories",
        )

    @mcp.tool()
    async def veeam_list_backups(
        actor: str,
        reason: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="veeam.backups.list",
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
        )
        return _response(
            "veeam.backups.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="veeam:backups",
        )

    @mcp.tool()
    async def veeam_list_restore_points(
        actor: str,
        reason: str,
        history_hours: int = 168,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="veeam.restore_points.list",
            limit=limit,
            cursor=cursor or None,
            parameters={"history_hours": history_hours},
            sample_size=sample_size,
        )
        return _response(
            "veeam.restore_points.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"historyHours": history_hours, **page},
            budget=budget,
            target="veeam:restore-points",
        )

    @mcp.tool()
    async def veeam_diagnostic_bundle(
        actor: str,
        reason: str,
        history_hours: int = 168,
        per_section_limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        bounded_limit = min(per_section_limit, settings.veeam_max_page_size)
        jobs = await _page(
            connector,
            budget,
            operation="veeam.jobs.states",
            limit=bounded_limit,
        )
        repositories = await _page(
            connector,
            budget,
            operation="veeam.repositories.states",
            limit=bounded_limit,
        )
        sessions = await _page(
            connector,
            budget,
            operation="veeam.sessions.list",
            limit=bounded_limit,
        )
        restore_points = await _page(
            connector,
            budget,
            operation="veeam.restore_points.list",
            limit=bounded_limit,
            parameters={"history_hours": history_hours},
        )
        job_rows = [item for item in jobs["items"] if isinstance(item, dict)]
        repository_rows = [item for item in repositories["items"] if isinstance(item, dict)]
        session_rows = [item for item in sessions["items"] if isinstance(item, dict)]
        restore_rows = [item for item in restore_points["items"] if isinstance(item, dict)]
        summary = DiagnosticSummary(
            jobs_returned=len(job_rows),
            jobs_failed_or_warning=sum(
                str(item.get("last_result", "")).casefold() in {"failed", "warning"}
                for item in job_rows
            ),
            repositories_returned=len(repository_rows),
            repositories_offline=sum(item.get("is_online") is False for item in repository_rows),
            repositories_out_of_date=sum(
                item.get("is_out_of_date") is True for item in repository_rows
            ),
            sessions_returned=len(session_rows),
            sessions_failed_or_warning=sum(
                str(item.get("result", "")).casefold() in {"failed", "warning"}
                for item in session_rows
            ),
            restore_points_returned=len(restore_rows),
            suspicious_or_infected_restore_points=sum(
                str(item.get("malware_status", "")).casefold() in {"suspicious", "infected"}
                for item in restore_rows
            ),
        ).model_dump(mode="json")
        return _response(
            "veeam.diagnostics.overview",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "historyHours": history_hours,
                "jobStates": jobs,
                "repositoryStates": repositories,
                "sessions": sessions,
                "restorePoints": restore_points,
                "summary": summary,
                "fanOutPerformed": False,
            },
            budget=budget,
            target="veeam:overview",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
