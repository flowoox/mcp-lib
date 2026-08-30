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

from .client import FreshdeskReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import ConversationSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "freshdesk.tickets.list",
        "freshdesk.tickets.get",
        "freshdesk.tickets.conversations",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="freshdesk.rest-v2.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.freshdesk_max_page_size,
        max_sample_size=settings.freshdesk_max_sample_size,
        request_timeout_seconds=settings.freshdesk_request_timeout_seconds,
        max_response_bytes=settings.freshdesk_max_response_bytes,
        max_concurrency=settings.freshdesk_max_concurrency,
        rate_limit_per_second=settings.freshdesk_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.freshdesk_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.freshdesk_budget_max_requests,
        max_items=settings.freshdesk_budget_max_items,
        max_response_bytes=settings.freshdesk_budget_max_response_bytes,
        max_fan_out=settings.freshdesk_budget_max_fan_out,
        total_timeout_seconds=settings.freshdesk_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="freshdesk-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="freshdesk-mcp")


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
    target: str = "freshdesk:tickets",
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
    connector = connector or ReadOnlyConnector(
        policy,
        FreshdeskReadOnlyTransport(settings),
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-freshdesk",))
    mcp = FastMCP(
        "Flowoox Freshdesk Diagnostics MCP",
        instructions=(
            "Bounded read-only Freshdesk API v2 diagnostics through fixed GET operations. "
            "Requester and agent identity, requester email/phone data, message bodies, custom fields "
            "and attachment content are never returned. Arbitrary search queries, arbitrary API paths "
            "and all ticket or conversation mutations are not exposed."
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
            max_page_number=settings.freshdesk_max_page_number,
        )

    @mcp.tool()
    async def freshdesk_list_tickets(
        actor: str,
        reason: str,
        filter: Literal["new_and_my_open", "watching", "spam", "deleted"] | None = None,
        updated_since: str = "",
        order_by: Literal["created_at", "due_by", "updated_at", "status"] = "updated_at",
        order_type: Literal["asc", "desc"] = "desc",
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters: dict[str, Any] = {
            "updated_since": updated_since,
            "order_by": order_by,
            "order_type": order_type,
        }
        if filter is not None:
            parameters["filter"] = filter
        page = await _page(
            connector,
            budget,
            operation="freshdesk.tickets.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "freshdesk.tickets.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def freshdesk_get_ticket(
        actor: str,
        reason: str,
        ticket_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="freshdesk.tickets.get",
            limit=1,
            parameters={"ticket_id": ticket_id},
        )
        return _response(
            "freshdesk.tickets.get",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"freshdesk:ticket:{ticket_id}",
        )

    @mcp.tool()
    async def freshdesk_list_conversation_metadata(
        actor: str,
        reason: str,
        ticket_id: str,
        limit: int = 30,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="freshdesk.tickets.conversations",
            limit=limit,
            cursor=cursor or None,
            parameters={"ticket_id": ticket_id},
            sample_size=sample_size,
        )
        return _response(
            "freshdesk.tickets.conversations",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"freshdesk:ticket:{ticket_id}",
        )

    @mcp.tool()
    async def freshdesk_diagnostic_bundle(
        actor: str,
        reason: str,
        ticket_id: str,
        conversation_limit: int = 20,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        ticket = await _page(
            connector,
            budget,
            operation="freshdesk.tickets.get",
            limit=1,
            parameters={"ticket_id": ticket_id},
        )
        conversations = await _page(
            connector,
            budget,
            operation="freshdesk.tickets.conversations",
            limit=min(conversation_limit, settings.freshdesk_max_page_size),
            parameters={"ticket_id": ticket_id},
        )
        items = [item for item in conversations["items"] if isinstance(item, dict)]
        summary = ConversationSummary(
            total=len(items),
            incoming=sum(item.get("incoming") is True for item in items),
            outgoing=sum(item.get("incoming") is False for item in items),
            private=sum(item.get("private") is True for item in items),
            with_attachments=sum((item.get("attachment_count") or 0) > 0 for item in items),
        ).model_dump(mode="json")
        output = {
            "ticketId": ticket_id,
            "ticket": ticket,
            "recentConversationMetadata": conversations,
            "conversationSummary": summary,
        }
        return _response(
            "freshdesk.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=output,
            budget=budget,
            target=f"freshdesk:ticket:{ticket_id}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
