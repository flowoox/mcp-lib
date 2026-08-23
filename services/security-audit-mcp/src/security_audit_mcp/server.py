from __future__ import annotations

import json
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

from .config import Settings
from .contract import capabilities
from .evaluator import evaluate_evidence
from .models import EvidenceBatch


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=1,
        max_items=settings.security_audit_budget_max_items,
        max_response_bytes=settings.security_audit_budget_max_response_bytes,
        max_fan_out=1,
        total_timeout_seconds=settings.security_audit_budget_timeout_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="security-audit-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="security-audit-mcp")


def _reason(value: str) -> str:
    normalized = value.strip()
    if not 1 <= len(normalized) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return normalized


def _observe_response(
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    output: dict[str, Any],
    budget: QueryBudget,
    evidence_count: int,
) -> dict[str, Any]:
    context = _operation_context(actor, correlation_id)
    result_output = dict(output)
    result_output["queryBudget"] = budget.snapshot().model_dump(mode="json")
    result = OperationResult(
        operation="security.audit.evaluate",
        phase=OperationPhase.OBSERVE,
        status=OperationStatus.SUCCEEDED,
        context=context,
        output=result_output,
    )
    audit = AuditEvent(
        operation="security.audit.evaluate",
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target="normalized-infrastructure-evidence",
        status=OperationStatus.SUCCEEDED,
        metadata={
            "reason": _reason(reason),
            "evidence_count": evidence_count,
            "finding_count": len(output.get("findings", [])),
        },
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


def create_server(settings: Settings | None = None) -> FastMCP:
    settings = settings or Settings()
    budget_limits = _budget_limits(settings)
    security = build_mcp_server_security(settings, service_hosts=("mcp-security-audit",))
    mcp = FastMCP(
        "Flowoox Infrastructure Security Audit MCP",
        instructions=(
            "Read-only policy engine for bounded typed facts produced by specialized infrastructure MCPs. "
            "It has no privileged backend identity, no arbitrary policy/query/command surface and never performs changes."
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
        """Return the fixed audit contract and control catalog."""
        return capabilities(
            budget_limits,
            max_evidence=settings.security_audit_max_evidence,
        )

    @mcp.tool()
    async def security_audit_evaluate(
        actor: str,
        reason: str,
        batch: EvidenceBatch,
        include_passed: bool = False,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Evaluate bounded typed evidence without querying or mutating infrastructure backends."""
        if len(batch.facts) > settings.security_audit_max_evidence:
            raise ValueError("evidence batch exceeds configured per-call limit")
        budget = QueryBudget(budget_limits)
        evaluation = evaluate_evidence(batch.facts, include_passed=include_passed)
        output = evaluation.model_dump(mode="json")
        serialized = json.dumps(
            output,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        budget.record_response(
            items=evaluation.summary.evaluated_controls,
            response_bytes=len(serialized),
        )
        return _observe_response(
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output=output,
            budget=budget,
            evidence_count=len(batch.facts),
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
