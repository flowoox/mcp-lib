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

from .client import DockerApiTransport
from .config import Settings
from .contract import capabilities

_CONNECTOR_OPERATIONS = frozenset(
    {
        "docker.system.ping",
        "docker.system.info",
        "docker.containers.list",
        "docker.containers.logs",
        "docker.events.list",
    }
)


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="docker.engine.readonly",
        allowed_operations=_CONNECTOR_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.docker_max_page_size,
        max_sample_size=settings.docker_max_sample_size,
        request_timeout_seconds=settings.docker_request_timeout_seconds,
        max_response_bytes=settings.docker_max_response_bytes,
        max_concurrency=settings.docker_max_concurrency,
        rate_limit_per_second=settings.docker_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.docker_cache_max_age_seconds,
    )


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.docker_budget_max_requests,
        max_items=settings.docker_budget_max_items,
        max_response_bytes=settings.docker_budget_max_response_bytes,
        max_fan_out=settings.docker_budget_max_fan_out,
        total_timeout_seconds=settings.docker_budget_timeout_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="docker-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="docker-mcp")


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
    target: str = "docker-host",
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


def _one(page_items: list[Any], operation: str) -> dict[str, Any]:
    if len(page_items) != 1 or not isinstance(page_items[0], dict):
        raise RuntimeError(f"{operation} returned an invalid normalized result")
    return page_items[0]


def create_server(
    settings: Settings | None = None,
    connector: ReadOnlyConnector | None = None,
) -> FastMCP:
    settings = settings or Settings()
    connector_policy = _connector_policy(settings)
    budget_limits = _budget_limits(settings)
    connector = connector or ReadOnlyConnector(
        connector_policy,
        DockerApiTransport(settings),
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-docker",))
    mcp = FastMCP(
        "Flowoox Docker Diagnostics MCP",
        instructions=(
            "Bounded read-only Docker diagnostics. The service exposes fixed GET operations only, "
            "requires an explicitly attested read-only backend, never follows live log or event "
            "streams, and never exposes Docker exec, arbitrary API paths, environment variables, "
            "labels, commands or raw inspect payloads."
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
        """Return the stable Docker diagnostics contract without backend URL or credentials."""
        return capabilities(
            connector.policy,
            budget_limits,
            direct_socket_override_enabled=settings.docker_allow_direct_socket,
            max_log_window_seconds=settings.docker_max_log_window_seconds,
            max_event_window_seconds=settings.docker_max_event_window_seconds,
        )

    @mcp.tool()
    async def docker_observe_health(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Return bounded Docker daemon and host-resource health metadata."""
        budget = QueryBudget(budget_limits)
        ping = await connector.execute(
            ReadOnlyQuery(operation="docker.system.ping", page=PageRequest(limit=1)),
            budget,
        )
        info = await connector.execute(
            ReadOnlyQuery(operation="docker.system.info", page=PageRequest(limit=1)),
            budget,
        )
        return _observe_response(
            "docker.health.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "reachable": bool(_one(ping.items, "docker.system.ping").get("ok")),
                "system": _one(info.items, "docker.system.info"),
                "cacheHint": info.cache_hint.model_dump(mode="json") if info.cache_hint else None,
            },
            budget=budget,
        )

    @mcp.tool()
    async def docker_list_containers(
        actor: str,
        reason: str,
        include_stopped: bool = False,
        limit: int = 50,
        sample_size: int | None = None,
        sample_strategy: Literal["head", "even"] = "even",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Return bounded normalized containers without secret-bearing raw fields."""
        budget = QueryBudget(budget_limits)
        sample = (
            SampleRequest(size=sample_size, strategy=sample_strategy)
            if sample_size is not None
            else None
        )
        page = await connector.execute(
            ReadOnlyQuery(
                operation="docker.containers.list",
                parameters={"include_stopped": include_stopped},
                page=PageRequest(limit=limit),
                sample=sample,
            ),
            budget,
        )
        return _observe_response(
            "docker.containers.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "containers": page.items,
                "returned": len(page.items),
                "truncated": page.truncated,
                "sampled": page.sampled,
                "cacheHint": page.cache_hint.model_dump(mode="json") if page.cache_hint else None,
            },
            budget=budget,
        )

    @mcp.tool()
    async def docker_container_logs(
        actor: str,
        reason: str,
        container_id: str,
        tail: int = 50,
        since_seconds_ago: int = 300,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Return a finite bounded historical log tail; live follow is never enabled."""
        budget = QueryBudget(budget_limits)
        page = await connector.execute(
            ReadOnlyQuery(
                operation="docker.containers.logs",
                parameters={
                    "container_id": container_id,
                    "since_seconds_ago": since_seconds_ago,
                },
                page=PageRequest(limit=tail),
            ),
            budget,
        )
        return _observe_response(
            "docker.containers.logs",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            target=f"docker-container:{container_id[:128]}",
            output={
                "lines": page.items,
                "returned": len(page.items),
                "truncated": page.truncated,
                "redaction": "best-effort credential-pattern redaction; treat remaining log content as sensitive",
            },
            budget=budget,
        )

    @mcp.tool()
    async def docker_recent_events(
        actor: str,
        reason: str,
        object_type: Literal["container", "image", "volume", "network", "daemon"] = "container",
        since_seconds_ago: int = 60,
        limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Return a finite recent Docker event window with minimized actor attributes."""
        budget = QueryBudget(budget_limits)
        page = await connector.execute(
            ReadOnlyQuery(
                operation="docker.events.list",
                parameters={
                    "since_seconds_ago": since_seconds_ago,
                    "object_types": [object_type],
                },
                page=PageRequest(limit=limit),
            ),
            budget,
        )
        return _observe_response(
            "docker.events.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "objectType": object_type,
                "events": page.items,
                "returned": len(page.items),
                "truncated": page.truncated,
            },
            budget=budget,
        )

    @mcp.tool()
    async def docker_diagnostic_bundle(
        actor: str,
        reason: str,
        include_stopped: bool = False,
        limit: int = 25,
        sample_size: int | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Aggregate health and sampled container relationships in one bounded budget."""
        budget = QueryBudget(budget_limits)
        ping = await connector.execute(
            ReadOnlyQuery(operation="docker.system.ping", page=PageRequest(limit=1)),
            budget,
        )
        info = await connector.execute(
            ReadOnlyQuery(operation="docker.system.info", page=PageRequest(limit=1)),
            budget,
        )
        sample = SampleRequest(size=sample_size) if sample_size is not None else None
        containers = await connector.execute(
            ReadOnlyQuery(
                operation="docker.containers.list",
                parameters={"include_stopped": include_stopped},
                page=PageRequest(limit=limit),
                sample=sample,
                aggregated=True,
            ),
            budget,
        )
        return _observe_response(
            "docker.diagnostics.bundle",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "reachable": bool(_one(ping.items, "docker.system.ping").get("ok")),
                "system": _one(info.items, "docker.system.info"),
                "containers": containers.items,
                "containerResult": {
                    "returned": len(containers.items),
                    "truncated": containers.truncated,
                    "sampled": containers.sampled,
                },
            },
            budget=budget,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
