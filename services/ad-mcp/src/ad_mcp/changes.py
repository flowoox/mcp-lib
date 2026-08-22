from __future__ import annotations

from typing import Any
from uuid import UUID

from mcp_common.approval_grants import verify_approval_grant
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
    Verification,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator


class MutationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=8, max_length=128)
    approval_grant: str = Field(min_length=16, max_length=8192)


class UserEnabledRequest(MutationInput):
    identity: str = Field(min_length=1, max_length=512)
    enabled: bool

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return clean_identity(value)


class GroupMembershipRequest(MutationInput):
    user_identity: str = Field(min_length=1, max_length=512)
    group_identity: str = Field(min_length=1, max_length=512)
    present: bool

    @field_validator("user_identity", "group_identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return clean_identity(value)


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=8, max_length=128)


def clean_identity(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("identity must not be blank")
    if any(ord(character) < 32 for character in value):
        raise ValueError("identity must not contain control characters")
    return value


def operation_context(correlation_id: str, *, idempotency_key: str | None = None) -> OperationContext:
    value = correlation_id.strip()
    kwargs: dict[str, Any] = {
        "actor": "mcp-client",
        "source": "ad-mcp",
        "idempotency_key": idempotency_key,
    }
    if value:
        try:
            kwargs["correlation_id"] = UUID(value)
        except ValueError as exc:
            raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(**kwargs)


def user_enabled_target(identity: str) -> str:
    return f"user:{clean_identity(identity)}"


def group_membership_target(user_identity: str, group_identity: str) -> str:
    user = clean_identity(user_identity)
    group = clean_identity(group_identity)
    return f"user:{user}|group:{group}"


def build_user_enabled_plan(
    *,
    identity: str,
    enabled: bool,
    current: dict[str, Any],
    correlation_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    context = operation_context(correlation_id, idempotency_key=idempotency_key)
    target = user_enabled_target(identity)
    before = bool(current.get("enabled"))
    plan = ChangePlan(
        operation="ad.user.enabled.change",
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="set-user-enabled",
                target=target,
                reversible=True,
                rollback_action=f"restore enabled={str(before).lower()}",
            )
        ],
        pre_state={"enabled": before, "objectGuid": current.get("objectGuid")},
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason="Enabling or disabling a directory identity can affect access and requires approval.",
        ),
    )
    audit = AuditEvent(
        operation="ad.user.enabled.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={"requestedEnabled": enabled},
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "audit": audit.model_dump(mode="json"),
        "alreadySatisfied": before == enabled,
    }


def build_group_membership_plan(
    *,
    user_identity: str,
    group_identity: str,
    present: bool,
    current_present: bool,
    correlation_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    context = operation_context(correlation_id, idempotency_key=idempotency_key)
    target = group_membership_target(user_identity, group_identity)
    plan = ChangePlan(
        operation="ad.user.group-membership.change",
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="set-direct-group-membership",
                target=target,
                reversible=True,
                rollback_action=f"restore present={str(current_present).lower()}",
            )
        ],
        pre_state={"present": current_present},
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason="Security-group membership can grant or revoke access and requires approval.",
        ),
    )
    audit = AuditEvent(
        operation="ad.user.group-membership.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={"requestedPresent": present},
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "audit": audit.model_dump(mode="json"),
        "alreadySatisfied": current_present == present,
    }


def authorize_change(
    *,
    grant: str,
    secret: str,
    operation: str,
    target: str,
    idempotency_key: str,
) -> Approval:
    return verify_approval_grant(
        grant,
        secret,
        operation=operation,
        target=target,
        idempotency_key=idempotency_key,
    )


def change_response(
    *,
    operation: str,
    target: str,
    correlation_id: str,
    idempotency_key: str,
    changed: bool,
    output: dict[str, Any],
    approval: Approval,
    verification: Verification,
) -> dict[str, Any]:
    context = operation_context(correlation_id, idempotency_key=idempotency_key)
    status = OperationStatus.SUCCEEDED if verification.passed else OperationStatus.FAILED
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.CHANGE,
        status=status,
        context=context,
        changed=changed,
        output=output,
        verification=[verification],
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=status,
        changed=changed,
        metadata={
            "approvalState": approval.state.value,
            "approver": approval.approver,
            "verificationPassed": verification.passed,
        },
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


def verify_response(
    *,
    operation: str,
    target: str,
    correlation_id: str,
    check: str,
    passed: bool,
    details: dict[str, Any],
) -> dict[str, Any]:
    context = operation_context(correlation_id)
    verification = Verification(check=check, passed=passed, details=details)
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.VERIFY,
        status=OperationStatus.SUCCEEDED if passed else OperationStatus.FAILED,
        context=context,
        verification=[verification],
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.VERIFY,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=target,
        status=result.status,
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload
