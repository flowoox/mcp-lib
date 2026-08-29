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

from .client import ManageEngineMdmReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import CommandStatusSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "manageengine_mdm.devices.list",
        "manageengine_mdm.devices.scan_status",
        "manageengine_mdm.devices.command_history",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="manageengine-mdm.rest-v1.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.mdm_max_page_size,
        max_sample_size=settings.mdm_max_sample_size,
        request_timeout_seconds=settings.mdm_request_timeout_seconds,
        max_response_bytes=settings.mdm_max_response_bytes,
        max_concurrency=settings.mdm_max_concurrency,
        rate_limit_per_second=settings.mdm_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.mdm_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.mdm_budget_max_requests,
        max_items=settings.mdm_budget_max_items,
        max_response_bytes=settings.mdm_budget_max_response_bytes,
        max_fan_out=settings.mdm_budget_max_fan_out,
        total_timeout_seconds=settings.mdm_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="manageengine-mdm-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="manageengine-mdm-mcp")


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
    target: str = "manageengine-mdm:fleet",
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
        ManageEngineMdmReadOnlyTransport(settings),
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-manageengine-mdm",))
    mcp = FastMCP(
        "Flowoox ManageEngine MDM Diagnostics MCP",
        instructions=(
            "Bounded read-only ManageEngine Mobile Device Manager Plus diagnostics through fixed "
            "REST v1 GET operations. The public projection excludes IMEI, serial numbers, UDIDs, "
            "assigned-user PII, locations, firmware passwords, APN credentials and command initiator "
            "identity. Arbitrary API paths and all device actions or mutations are never exposed."
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
            auth_mode=settings.mdm_auth_mode,
            customer_scope_configured=bool(settings.mdm_customer_id),
        )

    @mcp.tool()
    async def mdm_list_devices(
        actor: str,
        reason: str,
        platform: Literal["ios", "android", "windows", "macos", "tvos"] | None = None,
        search: str = "",
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        parameters: dict[str, Any] = {}
        if platform is not None:
            parameters["platform"] = platform
        if search.strip():
            parameters["search"] = search
        page = await _page(
            connector,
            budget,
            operation="manageengine_mdm.devices.list",
            limit=limit,
            cursor=cursor or None,
            parameters=parameters,
            sample_size=sample_size,
            sample_strategy=sample_strategy,
        )
        return _response(
            "manageengine_mdm.devices.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
        )

    @mcp.tool()
    async def mdm_get_scan_status(
        actor: str,
        reason: str,
        device_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="manageengine_mdm.devices.scan_status",
            limit=1,
            parameters={"device_id": device_id},
        )
        return _response(
            "manageengine_mdm.devices.scan_status",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"manageengine-mdm:device:{device_id}",
        )

    @mcp.tool()
    async def mdm_list_command_history(
        actor: str,
        reason: str,
        device_id: str,
        days: int = 7,
        limit: int = 25,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="manageengine_mdm.devices.command_history",
            limit=limit,
            cursor=cursor or None,
            parameters={"device_id": device_id, "days": days},
            sample_size=sample_size,
        )
        return _response(
            "manageengine_mdm.devices.command_history",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"manageengine-mdm:device:{device_id}",
        )

    @mcp.tool()
    async def mdm_diagnostic_bundle(
        actor: str,
        reason: str,
        device_id: str,
        history_days: int = 7,
        history_limit: int = 20,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        scan = await _page(
            connector,
            budget,
            operation="manageengine_mdm.devices.scan_status",
            limit=1,
            parameters={"device_id": device_id},
        )
        history = await _page(
            connector,
            budget,
            operation="manageengine_mdm.devices.command_history",
            limit=min(history_limit, settings.mdm_max_page_size),
            parameters={"device_id": device_id, "days": history_days},
        )
        statuses = Counter(
            str(item.get("command_status", "unknown"))
            for item in history["items"]
            if isinstance(item, dict)
        )
        output = {
            "deviceId": device_id,
            "scanStatus": scan,
            "recentCommandHistory": history,
            "commandStatusSummary": CommandStatusSummary(
                total=sum(statuses.values()),
                by_status=dict(sorted(statuses.items())),
            ).model_dump(mode="json"),
        }
        return _response(
            "manageengine_mdm.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=output,
            budget=budget,
            target=f"manageengine-mdm:device:{device_id}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
