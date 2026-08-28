from __future__ import annotations

from collections import Counter
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

from .client import N8nReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import ExecutionStatusSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "n8n.workflows.list",
        "n8n.executions.list",
        "n8n.executions.get",
    }
)
_EXECUTION_STATUSES = frozenset(
    {"error", "success", "running", "waiting", "canceled", "crashed", "new"}
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="n8n.public-api.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.n8n_max_page_size,
        max_sample_size=settings.n8n_max_sample_size,
        request_timeout_seconds=settings.n8n_request_timeout_seconds,
        max_response_bytes=settings.n8n_max_response_bytes,
        max_concurrency=settings.n8n_max_concurrency,
        rate_limit_per_second=settings.n8n_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.n8n_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.n8n_budget_max_requests,
        max_items=settings.n8n_budget_max_items,
        max_response_bytes=settings.n8n_budget_max_response_bytes,
        max_fan_out=settings.n8n_budget_max_fan_out,
        total_timeout_seconds=settings.n8n_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="n8n-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="n8n-mcp")


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
    target: str = "n8n:automation",
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


def _workflow_parameter(workflow_id: str) -> dict[str, Any]:
    value = workflow_id.strip()
    return {"workflow_id": value} if value else {}


def create_server(
    settings: Settings | None = None,
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(policy, N8nReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-n8n",))
    mcp = FastMCP(
        "Flowoox n8n Diagnostics MCP",
        instructions=(
            "Bounded read-only n8n diagnostics through fixed Public API v1 GET operations. "
            "Workflow definitions, node parameters, execution payload data, credentials, arbitrary API "
            "paths, workflow triggers and mutations are never exposed. Authorization relies on the "
            "deployment API identity and optional workflow allowlist, never on projectId filtering."
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
            workflow_allowlist_configured=bool(settings.allowed_workflow_ids),
        )

    @mcp.tool()
    async def n8n_list_workflows(
        actor: str,
        reason: str,
        active: bool | None = None,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters: dict[str, Any] = {}
        if active is not None:
            parameters["active"] = active
        page = await _page(
            connector,
            budget,
            operation="n8n.workflows.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "n8n.workflows.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def n8n_list_executions(
        actor: str,
        reason: str,
        workflow_id: str = "",
        status: str = "",
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        if status and status not in _EXECUTION_STATUSES:
            raise ValueError("status is not in the fixed execution-state allowlist")
        budget = QueryBudget(budget_limits)
        parameters = _workflow_parameter(workflow_id)
        if status:
            parameters["status"] = status
        page = await _page(
            connector,
            budget,
            operation="n8n.executions.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        target = (
            f"n8n:workflow:{workflow_id.strip()}" if workflow_id.strip() else "n8n:automation"
        )
        return _response(
            "n8n.executions.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=target,
        )

    @mcp.tool()
    async def n8n_get_execution(
        actor: str,
        reason: str,
        execution_id: str,
        workflow_id: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters = {"execution_id": execution_id}
        parameters.update(_workflow_parameter(workflow_id))
        page = await _page(
            connector,
            budget,
            operation="n8n.executions.get",
            limit=1,
            parameters=parameters,
        )
        return _response(
            "n8n.execution.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"n8n:execution:{execution_id}",
        )

    @mcp.tool()
    async def n8n_diagnostic_bundle(
        actor: str,
        reason: str,
        workflow_id: str = "",
        item_limit: int = 25,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        workflow_scope = _workflow_parameter(workflow_id)
        workflows = await _page(
            connector,
            budget,
            operation="n8n.workflows.list",
            limit=min(item_limit, settings.n8n_max_page_size),
            sample_size=min(item_limit, 10),
        )
        executions = await _page(
            connector,
            budget,
            operation="n8n.executions.list",
            limit=min(item_limit, settings.n8n_max_page_size),
            parameters=workflow_scope,
        )
        statuses = Counter(
            str(item.get("status", "unknown"))
            for item in executions["items"]
            if isinstance(item, dict)
        )
        summary = ExecutionStatusSummary(
            total=sum(statuses.values()),
            by_status=dict(sorted(statuses.items())),
        ).model_dump(mode="json")
        output = {
            "workflows": workflows,
            "recentExecutions": executions,
            "executionStatusSummary": summary,
            "scope": {
                "workflowId": workflow_id.strip() or None,
                "projectIdUsed": False,
            },
        }
        target = (
            f"n8n:workflow:{workflow_id.strip()}" if workflow_id.strip() else "n8n:automation"
        )
        return _response(
            "n8n.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=output,
            budget=budget,
            target=target,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
