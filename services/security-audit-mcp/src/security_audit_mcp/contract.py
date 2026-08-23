from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits

from .evaluator import rule_catalog
from .models import EvidenceSource

CONTRACT = "flowoox.security-audit"
CONTRACT_VERSION = "1.0.0"

TOOL_POLICIES = (
    ToolPolicy(
        name="security.audit.evaluate",
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
    ),
)


def capabilities(
    budget_limits: QueryBudgetLimits,
    *,
    max_evidence: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "writes_enabled": False,
            "direct_privileged_backend": False,
            "arbitrary_policy_input": False,
            "arbitrary_query_or_command": False,
            "max_evidence_per_call": max_evidence,
            "query_budget": budget_limits.model_dump(mode="json"),
            "accepted_sources": [source.value for source in EvidenceSource],
            "orchestration_model": (
                "specialized MCPs observe their own backends; n8n/agents normalize bounded facts; "
                "this service evaluates only the fixed evidence and control catalog"
            ),
        },
        "capabilities": [
            {
                "id": policy.name,
                "phase": policy.phase.value,
                "risk": policy.risk.value,
                "requires_approval": policy.requires_approval,
                "description": "Evaluate bounded typed evidence against the fixed product-neutral security control catalog.",
            }
            for policy in TOOL_POLICIES
        ],
        "controls": rule_catalog(),
    }
