from __future__ import annotations

import asyncio
from typing import Any, Callable
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

from .config import Settings
from .contract import capabilities
from .diagnostics import (
    diagnostic_bundle as build_diagnostic_bundle,
    dns_result,
    route_selection as build_route_selection,
    subnet_validation,
    tcp_probe,
)
from .policy import TargetPolicy, validate_port


def _context(correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor="mcp-client", source="network-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor="mcp-client", source="network-mcp")


def _observe_response(
    operation: str,
    correlation_id: str,
    output: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    context = _context(correlation_id)
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        status=OperationStatus.SUCCEEDED,
        context=context,
        output=output,
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=target,
        status=OperationStatus.SUCCEEDED,
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


async def _bounded_call(timeout_seconds: float, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(function, *args, **kwargs),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        raise TimeoutError("network diagnostic exceeded the configured operation timeout") from exc


def create_server(settings: Settings | None = None) -> FastMCP:
    settings = settings or Settings()
    policy = TargetPolicy(
        settings.network_allowed_cidrs,
        max_addresses=settings.network_max_resolved_addresses,
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-network",))
    mcp = FastMCP(
        "Flowoox Network Diagnostics MCP",
        instructions=(
            "Bounded network diagnostics only. Active probes resolve once and require every resulting "
            "IP address to fall inside NETWORK_ALLOWED_CIDRS. The service exposes no arbitrary shell, "
            "URL fetch, packet flood, port range scan, or caller-supplied command primitive."
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
        """Return the stable network diagnostic contract and active target boundary."""
        return capabilities(
            allowed_cidrs=settings.network_allowed_cidrs,
            max_ports_per_bundle=settings.network_max_ports_per_bundle,
        )

    @mcp.tool()
    async def dns_resolve(host: str, correlation_id: str = "") -> dict[str, Any]:
        """Resolve and authorize one bare hostname or IP before returning bounded DNS evidence."""
        target = await _bounded_call(
            settings.network_operation_timeout_seconds,
            policy.resolve,
            host,
        )
        return _observe_response(
            "network.dns.resolve",
            correlation_id,
            dns_result(target),
            target=f"host:{target.normalized_host}",
        )

    @mcp.tool()
    async def tcp_reachability(
        host: str,
        port: int,
        timeout_seconds: float = 3.0,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Probe one TCP port on one authorized target with a bounded timeout."""
        port = validate_port(port)
        if not 0.1 <= timeout_seconds <= settings.network_operation_timeout_seconds:
            raise ValueError(
                "timeout_seconds must be between 0.1 and NETWORK_OPERATION_TIMEOUT_SECONDS"
            )
        target = await _bounded_call(
            settings.network_operation_timeout_seconds,
            policy.resolve,
            host,
        )
        output = await _bounded_call(
            settings.network_operation_timeout_seconds,
            tcp_probe,
            target,
            port,
            timeout_seconds=timeout_seconds,
        )
        return _observe_response(
            "network.tcp.reachability",
            correlation_id,
            output,
            target=f"host:{target.normalized_host}|tcp:{port}",
        )

    @mcp.tool()
    async def route_selection(host: str, correlation_id: str = "") -> dict[str, Any]:
        """Return kernel source-address selection for an authorized target without shell execution."""
        target = await _bounded_call(
            settings.network_operation_timeout_seconds,
            policy.resolve,
            host,
        )
        output = await _bounded_call(
            settings.network_operation_timeout_seconds,
            build_route_selection,
            target,
        )
        return _observe_response(
            "network.route.selection",
            correlation_id,
            output,
            target=f"host:{target.normalized_host}",
        )

    @mcp.tool()
    async def subnet_validate(
        address: str,
        network: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Validate address/subnet membership and properties without network I/O."""
        output = subnet_validation(address, network)
        return _observe_response(
            "network.subnet.validate",
            correlation_id,
            output,
            target=f"network:{output['network']}",
        )

    @mcp.tool()
    async def diagnostic_bundle(
        host: str,
        ports: list[int],
        timeout_seconds: float = 3.0,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Return DNS, source-route selection and bounded TCP evidence for one authorized host."""
        if not 0.1 <= timeout_seconds <= settings.network_operation_timeout_seconds:
            raise ValueError(
                "timeout_seconds must be between 0.1 and NETWORK_OPERATION_TIMEOUT_SECONDS"
            )
        output = await _bounded_call(
            settings.network_operation_timeout_seconds * max(1, len(ports) + 1),
            build_diagnostic_bundle,
            policy,
            host,
            ports,
            timeout_seconds=timeout_seconds,
            max_ports=settings.network_max_ports_per_bundle,
        )
        normalized_host = str(output["dns"]["normalizedHost"])
        return _observe_response(
            "network.diagnostic.bundle",
            correlation_id,
            output,
            target=f"host:{normalized_host}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
