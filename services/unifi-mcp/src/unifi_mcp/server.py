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

from .client import UniFiReadOnlyTransport
from .config import Settings
from .contract import capabilities
from .models import SiteDiagnosticSummary

_CONNECTOR_OPERATIONS = frozenset(
    {
        "unifi.application.info",
        "unifi.sites.list",
        "unifi.devices.list",
        "unifi.devices.get",
        "unifi.devices.statistics.latest",
        "unifi.clients.list",
        "unifi.clients.get",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="unifi.network-integration.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.unifi_max_page_size,
        max_sample_size=settings.unifi_max_sample_size,
        request_timeout_seconds=settings.unifi_request_timeout_seconds,
        max_response_bytes=settings.unifi_max_response_bytes,
        max_concurrency=settings.unifi_max_concurrency,
        rate_limit_per_second=settings.unifi_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.unifi_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.unifi_budget_max_requests,
        max_items=settings.unifi_budget_max_items,
        max_response_bytes=settings.unifi_budget_max_response_bytes,
        max_fan_out=settings.unifi_budget_max_fan_out,
        total_timeout_seconds=settings.unifi_budget_timeout_seconds,
    )


def _context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="unifi-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="unifi-mcp")


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
    connector = connector or ReadOnlyConnector(policy, UniFiReadOnlyTransport(settings))
    security = build_mcp_server_security(settings, service_hosts=("mcp-unifi",))
    mcp = FastMCP(
        "Flowoox UniFi Network Diagnostics MCP",
        instructions=(
            "Bounded read-only diagnostics for the official UniFi Network Integration API. "
            "The service uses a fixed GET-only operation allowlist, exposes no filter DSL or "
            "caller-selected API path, and omits device/client IP and MAC addresses plus client names. "
            "The deployment must use a read-only UniFi identity/API key; configuration and action "
            "endpoints are intentionally absent."
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
        return capabilities(connector.policy, budget_limits, max_offset=settings.unifi_max_offset)

    @mcp.tool()
    async def unifi_get_application_info(
        actor: str, reason: str, correlation_id: str = ""
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(connector, budget, operation="unifi.application.info", limit=1)
        return _response(
            "unifi.application.info",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="unifi:application",
        )

    @mcp.tool()
    async def unifi_list_sites(
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
            operation="unifi.sites.list",
            limit=limit,
            cursor=cursor or None,
            sample_size=sample_size,
        )
        return _response(
            "unifi.sites.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target="unifi:sites",
        )

    @mcp.tool()
    async def unifi_list_devices(
        actor: str,
        reason: str,
        site_id: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="unifi.devices.list",
            limit=limit,
            cursor=cursor or None,
            parameters={"site_id": site_id},
            sample_size=sample_size,
        )
        return _response(
            "unifi.devices.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"unifi:site:{site_id}:devices",
        )

    @mcp.tool()
    async def unifi_get_device(
        actor: str, reason: str, site_id: str, device_id: str, correlation_id: str = ""
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="unifi.devices.get",
            limit=1,
            parameters={"site_id": site_id, "device_id": device_id},
        )
        return _response(
            "unifi.devices.get",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"unifi:site:{site_id}:device:{device_id}",
        )

    @mcp.tool()
    async def unifi_get_device_statistics(
        actor: str, reason: str, site_id: str, device_id: str, correlation_id: str = ""
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="unifi.devices.statistics.latest",
            limit=1,
            parameters={"site_id": site_id, "device_id": device_id},
        )
        return _response(
            "unifi.devices.statistics.latest",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"unifi:site:{site_id}:device:{device_id}",
        )

    @mcp.tool()
    async def unifi_list_clients(
        actor: str,
        reason: str,
        site_id: str,
        limit: int = 50,
        cursor: str = "",
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="unifi.clients.list",
            limit=limit,
            cursor=cursor or None,
            parameters={"site_id": site_id},
            sample_size=sample_size,
        )
        return _response(
            "unifi.clients.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"unifi:site:{site_id}:clients",
        )

    @mcp.tool()
    async def unifi_get_client(
        actor: str, reason: str, site_id: str, client_id: str, correlation_id: str = ""
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _page(
            connector,
            budget,
            operation="unifi.clients.get",
            limit=1,
            parameters={"site_id": site_id, "client_id": client_id},
        )
        return _response(
            "unifi.clients.get",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=page,
            budget=budget,
            target=f"unifi:site:{site_id}:client:{client_id}",
        )

    @mcp.tool()
    async def unifi_site_diagnostic_bundle(
        actor: str,
        reason: str,
        site_id: str,
        device_limit: int = 50,
        client_limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        devices = await _page(
            connector,
            budget,
            operation="unifi.devices.list",
            limit=min(device_limit, settings.unifi_max_page_size),
            parameters={"site_id": site_id},
        )
        clients = await _page(
            connector,
            budget,
            operation="unifi.clients.list",
            limit=min(client_limit, settings.unifi_max_page_size),
            parameters={"site_id": site_id},
        )
        device_rows = [item for item in devices["items"] if isinstance(item, dict)]
        client_rows = [item for item in clients["items"] if isinstance(item, dict)]
        client_types = Counter(str(item.get("client_type") or "UNKNOWN") for item in client_rows)
        summary = SiteDiagnosticSummary(
            devices_returned=len(device_rows),
            devices_online=sum(item.get("state") == "ONLINE" for item in device_rows),
            devices_offline_or_degraded=sum(
                item.get("state") not in {"ONLINE", "UPDATING"} for item in device_rows
            ),
            devices_firmware_updatable=sum(
                item.get("firmware_updatable") is True for item in device_rows
            ),
            clients_returned=len(client_rows),
            client_types=dict(client_types),
        ).model_dump(mode="json")
        return _response(
            "unifi.diagnostics.site",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "siteId": site_id,
                "deviceInventory": devices,
                "clientInventory": clients,
                "summary": summary,
                "fanOutPerformed": False,
            },
            budget=budget,
            target=f"unifi:site:{site_id}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
