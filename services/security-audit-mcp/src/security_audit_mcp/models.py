from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from mcp_common.operations import StrictModel
from pydantic import Field, field_validator, model_validator


class EvidenceSource(StrEnum):
    ACTIVE_DIRECTORY = "active_directory"
    NETWORK = "network"
    FORTIGATE = "fortigate"
    ENTRA = "entra"
    WINDOWS = "windows"


class EvidenceKind(StrEnum):
    AD_REPLICATION_FAILURES = "ad.replication_failures"
    AD_SECURE_CHANNEL_HEALTHY = "ad.secure_channel_healthy"
    NETWORK_FAILED_CHECKS = "network.failed_checks"
    FORTIGATE_HA_HEALTHY = "fortigate.ha_healthy"
    FORTIGATE_PERMISSIVE_POLICY_COUNT = "fortigate.permissive_policy_count"
    ENTRA_CONDITIONAL_ACCESS_ENABLED_COUNT = "entra.conditional_access_enabled_count"
    WINDOWS_REBOOT_PENDING = "windows.reboot_pending"
    WINDOWS_CRITICAL_EVENT_COUNT = "windows.critical_event_count"
    WINDOWS_FAILED_SERVICE_COUNT = "windows.failed_service_count"


KIND_SOURCE: dict[EvidenceKind, EvidenceSource] = {
    EvidenceKind.AD_REPLICATION_FAILURES: EvidenceSource.ACTIVE_DIRECTORY,
    EvidenceKind.AD_SECURE_CHANNEL_HEALTHY: EvidenceSource.ACTIVE_DIRECTORY,
    EvidenceKind.NETWORK_FAILED_CHECKS: EvidenceSource.NETWORK,
    EvidenceKind.FORTIGATE_HA_HEALTHY: EvidenceSource.FORTIGATE,
    EvidenceKind.FORTIGATE_PERMISSIVE_POLICY_COUNT: EvidenceSource.FORTIGATE,
    EvidenceKind.ENTRA_CONDITIONAL_ACCESS_ENABLED_COUNT: EvidenceSource.ENTRA,
    EvidenceKind.WINDOWS_REBOOT_PENDING: EvidenceSource.WINDOWS,
    EvidenceKind.WINDOWS_CRITICAL_EVENT_COUNT: EvidenceSource.WINDOWS,
    EvidenceKind.WINDOWS_FAILED_SERVICE_COUNT: EvidenceSource.WINDOWS,
}


class EvidenceFact(StrictModel):
    kind: EvidenceKind
    source: EvidenceSource
    subject: str = Field(min_length=1, max_length=200)
    source_operation: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    observed_at: datetime
    bool_value: bool | None = None
    int_value: int | None = Field(default=None, ge=0, le=1_000_000_000)

    @field_validator("subject")
    @classmethod
    def normalize_subject(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("subject must not be blank")
        return normalized

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_fact(self) -> EvidenceFact:
        if KIND_SOURCE[self.kind] != self.source:
            raise ValueError("evidence source does not match evidence kind")
        populated = int(self.bool_value is not None) + int(self.int_value is not None)
        if populated != 1:
            raise ValueError("exactly one of bool_value or int_value must be set")
        if self.kind in {
            EvidenceKind.AD_SECURE_CHANNEL_HEALTHY,
            EvidenceKind.FORTIGATE_HA_HEALTHY,
            EvidenceKind.WINDOWS_REBOOT_PENDING,
        } and self.bool_value is None:
            raise ValueError("boolean evidence kind requires bool_value")
        if self.kind not in {
            EvidenceKind.AD_SECURE_CHANNEL_HEALTHY,
            EvidenceKind.FORTIGATE_HA_HEALTHY,
            EvidenceKind.WINDOWS_REBOOT_PENDING,
        } and self.int_value is None:
            raise ValueError("integer evidence kind requires int_value")
        return self

    @property
    def value(self) -> bool | int:
        if self.bool_value is not None:
            return self.bool_value
        assert self.int_value is not None
        return self.int_value


class EvidenceBatch(StrictModel):
    facts: list[EvidenceFact] = Field(min_length=1, max_length=200)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ControlState(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class ControlResult(StrictModel):
    control_id: str = Field(pattern=r"^SEC-[A-Z]+-[0-9]{3}$")
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    state: ControlState
    source: EvidenceSource
    subject: str
    source_operation: str
    observed_at: datetime
    observed_value: bool | int
    expected: str = Field(min_length=1, max_length=200)
    remediation: str | None = Field(default=None, max_length=500)


class AuditSummary(StrictModel):
    evaluated_controls: int = Field(ge=0)
    passed_controls: int = Field(ge=0)
    failed_controls: int = Field(ge=0)
    stale_facts_ignored: int = Field(ge=0)
    by_severity: dict[Severity, int]


class AuditEvaluation(StrictModel):
    summary: AuditSummary
    findings: list[ControlResult]
    passed: list[ControlResult] = Field(default_factory=list)


def json_safe_value(value: Any) -> bool | int:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise TypeError("unsupported evidence value")
