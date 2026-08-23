from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DirectoryObject(StrictModel):
    distinguished_name: str
    object_classes: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class QueryResult(StrictModel):
    correlation_id: UUID = Field(default_factory=uuid4)
    count: int = Field(ge=0)
    truncated: bool = False
    objects: list[DirectoryObject] = Field(default_factory=list)


class Finding(StrictModel):
    check_id: str = Field(pattern=r"^AD-[A-Z0-9-]{3,64}$")
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = Field(min_length=1, max_length=2000)


class AuditReport(StrictModel):
    correlation_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scope: str = Field(min_length=1, max_length=500)
    findings: list[Finding] = Field(default_factory=list)
    observations: dict[str, Any] = Field(default_factory=dict)

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value

    @property
    def passed(self) -> bool:
        return not any(
            finding.severity in {Severity.HIGH, Severity.CRITICAL} for finding in self.findings
        )
