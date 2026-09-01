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
from .transport import PKIReadOnlyTransport

_BACKEND_OPERATIONS = frozenset(
    {
        "pki.ca.observe",
        "pki.certificate.list_expiring",
        "pki.revocation_publication.observe",
        "pki.event.list",
    }
)


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.pki_budget_max_requests,
        max_items=settings.pki_budget_max_items,
        max_response_bytes=settings.pki_budget_max_response_bytes,
        max_fan_out=settings.pki_budget_max_fan_out,
        total_timeout_seconds=settings.pki_budget_timeout_seconds,
    )


def _connector_policy(settings: Settings) -> ReadOnlyConnectorPolicy:
    return ReadOnlyConnectorPolicy(
        connector_name="pki-adcs-jea",
        allowed_operations=_BACKEND_OPERATIONS,
        require_read_only_backend=True,
        max_page_size=settings.pki_max_page_size,
        max_sample_size=settings.pki_max_sample_size,
        request_timeout_seconds=settings.pki_request_timeout_seconds,
        max_response_bytes=settings.pki_max_response_bytes,
        max_concurrency=settings.pki_max_concurrency,
        rate_limit_per_second=settings.pki_rate_limit_per_second,
        aggregate_before_fan_out=True,
        default_cache_max_age_seconds=settings.pki_cache_max_age_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="pki-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="pki-mcp")


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
    parameters: dict[str, Any] | None = None,
) -> ReadOnlyPage:
    query_parameters = {"target_id": target_id}
    query_parameters.update(parameters or {})
    return await connector.execute(
        ReadOnlyQuery(
            operation=operation,
            parameters=query_parameters,
            page=PageRequest(limit=limit),
            aggregated=True,
        ),
        budget,
    )


def _page(page: ReadOnlyPage) -> dict[str, Any]:
    return {
        "items": page.items,
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
        connector = ReadOnlyConnector(connector_policy, PKIReadOnlyTransport(settings))

    security = build_mcp_server_security(settings, service_hosts=("mcp-pki",))
    mcp = FastMCP(
        "Flowoox PKI Diagnostics MCP",
        instructions=(
            "Bounded read-only Microsoft AD CS diagnostics over configured logical target aliases. "
            "Production requires a dedicated Kerberos WinRM/JEA endpoint and an identity explicitly "
            "granted only the CA database view/read permissions needed by the fixed probes. "
            "No certutil, arbitrary PowerShell, certificate issuance/revocation, private-key access, "
            "CA/template mutation or unrestricted certificate export is exposed."
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
        return capabilities(connector_policy, budget_limits)

    @mcp.tool()
    async def pki_observe_ca(
        actor: str,
        reason: str,
        target_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(connector, budget, "pki.ca.observe", target_id=target_id, limit=1)
        return _response(
            "pki.ca.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"ca": page.items[0] if page.items else None},
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def pki_list_expiring_certificates(
        actor: str,
        reason: str,
        target_id: str,
        expiry_days: int = 30,
        limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "pki.certificate.list_expiring",
            target_id=target_id,
            limit=limit,
            parameters={"expiry_days": expiry_days},
        )
        return _response(
            "pki.certificate.list_expiring",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def pki_observe_revocation_publication(
        actor: str,
        reason: str,
        target_id: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "pki.revocation_publication.observe",
            target_id=target_id,
            limit=1,
        )
        return _response(
            "pki.revocation_publication.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"revocationPublication": page.items[0] if page.items else None},
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def pki_list_events(
        actor: str,
        reason: str,
        target_id: str,
        lookback_minutes: int = 60,
        level: str = "error",
        limit: int = 50,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        page = await _query(
            connector,
            budget,
            "pki.event.list",
            target_id=target_id,
            limit=limit,
            parameters={"lookback_minutes": lookback_minutes, "level": level},
        )
        return _response(
            "pki.event.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=_page(page),
            budget=budget,
            target=target_id,
        )

    @mcp.tool()
    async def pki_diagnostic_bundle(
        actor: str,
        reason: str,
        target_id: str,
        expiry_days: int = 30,
        max_expiring: int = 25,
        max_events: int = 25,
        event_lookback_minutes: int = 240,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)

        ca = await _query(connector, budget, "pki.ca.observe", target_id=target_id, limit=1)
        revocation = await _query(
            connector,
            budget,
            "pki.revocation_publication.observe",
            target_id=target_id,
            limit=1,
        )
        expiring = await _query(
            connector,
            budget,
            "pki.certificate.list_expiring",
            target_id=target_id,
            limit=max_expiring,
            parameters={"expiry_days": expiry_days},
        )
        events = await _query(
            connector,
            budget,
            "pki.event.list",
            target_id=target_id,
            limit=max_events,
            parameters={"lookback_minutes": event_lookback_minutes, "level": "warning"},
        )
        return _response(
            "pki.diagnose",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "ca": ca.items[0] if ca.items else None,
                "revocationPublication": revocation.items[0] if revocation.items else None,
                "expiringCertificates": expiring.items,
                "events": events.items,
                "truncated": {
                    "expiringCertificates": expiring.truncated,
                    "events": events.truncated,
                },
            },
            budget=budget,
            target=target_id,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
