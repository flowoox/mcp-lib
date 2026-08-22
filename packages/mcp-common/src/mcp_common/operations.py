from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")


class OperationPhase(StrEnum):
    OBSERVE = "observe"
    PLAN = "plan"
    CHANGE = "change"
    VERIFY = "verify"


class RiskLevel(StrEnum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalState(StrEnum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    APPROVED = "approved"
    DENIED = "denied"


class OperationStatus(StrEnum):
    PLANNED = "planned"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OperationContext(StrictModel):
    """Actor and request metadata propagated across an MCP operation."""

    correlation_id: UUID = Field(default_factory=uuid4)
    actor: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=100)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)

    @field_validator("actor", "source")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _IDEMPOTENCY_RE.fullmatch(value):
            raise ValueError(
                "idempotency_key must be 8-128 characters using letters, digits, '.', '_', ':', '/', or '-'"
            )
        return value


class Approval(StrictModel):
    state: ApprovalState = ApprovalState.NOT_REQUIRED
    approver: str | None = Field(default=None, min_length=1, max_length=200)
    reason: str | None = Field(default=None, min_length=1, max_length=1000)
    approved_at: datetime | None = None

    @model_validator(mode="after")
    def validate_decision(self) -> "Approval":
        if self.state == ApprovalState.APPROVED:
            if self.approver is None:
                raise ValueError("approved operations require an approver")
            if self.approved_at is None:
                raise ValueError("approved operations require approved_at")
        elif self.approved_at is not None:
            raise ValueError("approved_at is only valid for approved operations")
        return self


class ChangeStep(StrictModel):
    action: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=500)
    reversible: bool
    rollback_action: str | None = Field(default=None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def require_rollback_when_reversible(self) -> "ChangeStep":
        if self.reversible and self.rollback_action is None:
            raise ValueError("reversible steps require rollback_action")
        return self


class ChangePlan(StrictModel):
    """Provider-neutral representation of a proposed state change."""

    operation: str = Field(min_length=1, max_length=200)
    risk: RiskLevel
    context: OperationContext
    steps: list[ChangeStep] = Field(min_length=1, max_length=100)
    pre_state: dict[str, Any] = Field(default_factory=dict)
    approval: Approval = Field(default_factory=Approval)

    @model_validator(mode="after")
    def enforce_change_invariants(self) -> "ChangePlan":
        if self.risk == RiskLevel.READ_ONLY:
            raise ValueError("ChangePlan cannot use read_only risk")
        if self.context.idempotency_key is None:
            raise ValueError("state-changing plans require an idempotency_key")
        if self.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL} and self.approval.state not in {
            ApprovalState.REQUIRED,
            ApprovalState.APPROVED,
        }:
            raise ValueError("high and critical risk changes require an approval gate")
        return self

    def executable(self) -> bool:
        if self.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return self.approval.state == ApprovalState.APPROVED
        return self.approval.state not in {ApprovalState.REQUIRED, ApprovalState.DENIED}


class Verification(StrictModel):
    check: str = Field(min_length=1, max_length=300)
    passed: bool
    details: dict[str, Any] = Field(default_factory=dict)


class OperationResult(StrictModel):
    operation: str = Field(min_length=1, max_length=200)
    phase: OperationPhase
    status: OperationStatus
    context: OperationContext
    changed: bool = False
    output: dict[str, Any] = Field(default_factory=dict)
    verification: list[Verification] = Field(default_factory=list)
    rollback_performed: bool = False

    @model_validator(mode="after")
    def validate_result(self) -> "OperationResult":
        if self.phase != OperationPhase.CHANGE and self.changed:
            raise ValueError("only change-phase results may report changed=true")
        if self.rollback_performed and not self.changed:
            raise ValueError("rollback_performed requires changed=true")
        return self


class AuditEvent(StrictModel):
    """Structured, secret-free audit envelope for tool invocations."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    operation: str = Field(min_length=1, max_length=200)
    phase: OperationPhase
    risk: RiskLevel
    context: OperationContext
    target: str | None = Field(default=None, max_length=500)
    status: OperationStatus
    changed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class ToolPolicy(StrictModel):
    """Static declaration used to keep MCP tool registration explicit."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    phase: OperationPhase
    risk: RiskLevel
    requires_approval: bool = False

    @model_validator(mode="after")
    def validate_policy(self) -> "ToolPolicy":
        if self.phase == OperationPhase.OBSERVE and self.risk != RiskLevel.READ_ONLY:
            raise ValueError("observe tools must be read_only")
        if self.phase == OperationPhase.CHANGE and self.risk == RiskLevel.READ_ONLY:
            raise ValueError("change tools cannot be read_only")
        if self.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL} and not self.requires_approval:
            raise ValueError("high and critical risk tools must require approval")
        return self
