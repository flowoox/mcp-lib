from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from mcp_common.operations import (
    Approval,
    ApprovalState,
    AuditEvent,
    ChangePlan,
    ChangeStep,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
    ToolPolicy,
)


def context(*, key: str | None = "joiner:alice:2026-08-22") -> OperationContext:
    return OperationContext(
        correlation_id=uuid4(),
        actor="automation:test",
        source="pytest",
        idempotency_key=key,
    )


def test_observe_policy_is_explicitly_read_only() -> None:
    policy = ToolPolicy(name="ad.domain.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY)
    assert policy.requires_approval is False


def test_observe_policy_rejects_write_risk() -> None:
    with pytest.raises(ValidationError):
        ToolPolicy(name="ad.domain.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.MEDIUM)


def test_high_risk_change_requires_approval_gate_and_idempotency() -> None:
    step = ChangeStep(
        action="disable account",
        target="user/alice",
        reversible=True,
        rollback_action="enable account",
    )
    with pytest.raises(ValidationError):
        ChangePlan(operation="ad.user.disable", risk=RiskLevel.HIGH, context=context(key=None), steps=[step])
    with pytest.raises(ValidationError):
        ChangePlan(operation="ad.user.disable", risk=RiskLevel.HIGH, context=context(), steps=[step])


def test_approved_high_risk_plan_is_executable() -> None:
    plan = ChangePlan(
        operation="ad.user.disable",
        risk=RiskLevel.HIGH,
        context=context(),
        steps=[
            ChangeStep(
                action="disable account",
                target="user/alice",
                reversible=True,
                rollback_action="enable account",
            )
        ],
        approval=Approval(
            state=ApprovalState.APPROVED,
            approver="security@example.invalid",
            approved_at=datetime.now(timezone.utc),
        ),
    )
    assert plan.executable() is True


def test_required_approval_is_not_executable() -> None:
    plan = ChangePlan(
        operation="firewall.policy.delete",
        risk=RiskLevel.CRITICAL,
        context=context(key="fw:policy:1234"),
        steps=[ChangeStep(action="delete policy", target="policy/1234", reversible=False)],
        approval=Approval(state=ApprovalState.REQUIRED),
    )
    assert plan.executable() is False


def test_non_change_result_cannot_claim_mutation() -> None:
    with pytest.raises(ValidationError):
        OperationResult(
            operation="network.route.observe",
            phase=OperationPhase.OBSERVE,
            status=OperationStatus.SUCCEEDED,
            context=context(),
            changed=True,
        )


def test_audit_event_requires_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            timestamp=datetime(2026, 8, 22, 8, 0, 0),
            operation="ad.domain.observe",
            phase=OperationPhase.OBSERVE,
            risk=RiskLevel.READ_ONLY,
            context=context(),
            status=OperationStatus.SUCCEEDED,
        )


def test_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        OperationContext(actor="test", source="test", unexpected="nope")
