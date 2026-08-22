from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecuritySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domainMode: str
    forestMode: str
    minimumPasswordLength: int = Field(ge=0)
    passwordHistoryCount: int = Field(ge=0)
    complexityEnabled: bool
    reversibleEncryptionEnabled: bool
    lockoutThreshold: int = Field(ge=0)
    minimumPasswordAgeDays: float
    maximumPasswordAgeDays: float
    machineAccountQuota: int = Field(ge=0)
    recycleBinEnabled: bool


class BaselineProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minimum_password_length: int = Field(default=14, ge=8, le=128)
    minimum_password_history: int = Field(default=24, ge=0, le=1024)
    maximum_lockout_threshold: int = Field(default=10, ge=1, le=100)
    maximum_machine_account_quota: int = Field(default=0, ge=0, le=1000)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    severity: Severity
    title: str
    evidence: dict[str, Any]
    recommendation: str


class BaselineReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compliant: bool
    profile: BaselineProfile
    snapshot: SecuritySnapshot
    findings: list[Finding]


_LEGACY_DOMAIN_MODES = {
    "Windows2000Domain",
    "Windows2003InterimDomain",
    "Windows2003Domain",
    "Windows2008Domain",
    "Windows2008R2Domain",
    "Windows2012Domain",
    "Windows2012R2Domain",
}


def evaluate_security_snapshot(
    raw_snapshot: dict[str, Any], profile: BaselineProfile | None = None
) -> BaselineReport:
    snapshot = SecuritySnapshot.model_validate(raw_snapshot)
    profile = profile or BaselineProfile()
    findings: list[Finding] = []

    if snapshot.minimumPasswordLength < profile.minimum_password_length:
        findings.append(
            Finding(
                id="AD-PASSWORD-MIN-LENGTH",
                severity=Severity.MEDIUM,
                title="Minimum password length is below the selected baseline",
                evidence={
                    "configured": snapshot.minimumPasswordLength,
                    "minimum": profile.minimum_password_length,
                },
                recommendation=(
                    "Raise the domain password minimum length or use an equivalent stronger "
                    "authentication policy after validating application compatibility."
                ),
            )
        )

    if snapshot.passwordHistoryCount < profile.minimum_password_history:
        findings.append(
            Finding(
                id="AD-PASSWORD-HISTORY",
                severity=Severity.MEDIUM,
                title="Password history is below the selected baseline",
                evidence={
                    "configured": snapshot.passwordHistoryCount,
                    "minimum": profile.minimum_password_history,
                },
                recommendation="Increase password history after validating the organization policy.",
            )
        )

    if not snapshot.complexityEnabled:
        findings.append(
            Finding(
                id="AD-PASSWORD-COMPLEXITY",
                severity=Severity.HIGH,
                title="Domain password complexity is disabled",
                evidence={"complexityEnabled": False},
                recommendation="Enable a suitable password-strength control for domain accounts.",
            )
        )

    if snapshot.reversibleEncryptionEnabled:
        findings.append(
            Finding(
                id="AD-REVERSIBLE-PASSWORDS",
                severity=Severity.CRITICAL,
                title="Reversible password encryption is enabled",
                evidence={"reversibleEncryptionEnabled": True},
                recommendation=(
                    "Disable reversible password encryption unless a documented legacy exception "
                    "requires it, then rotate affected credentials."
                ),
            )
        )

    if snapshot.lockoutThreshold == 0:
        findings.append(
            Finding(
                id="AD-LOCKOUT-DISABLED",
                severity=Severity.MEDIUM,
                title="Account lockout threshold is disabled",
                evidence={"lockoutThreshold": 0},
                recommendation=(
                    "Adopt a lockout or smart-lockout strategy appropriate to the environment and "
                    "pair it with monitoring to reduce password-guessing risk."
                ),
            )
        )
    elif snapshot.lockoutThreshold > profile.maximum_lockout_threshold:
        findings.append(
            Finding(
                id="AD-LOCKOUT-THRESHOLD",
                severity=Severity.LOW,
                title="Account lockout threshold exceeds the selected baseline",
                evidence={
                    "configured": snapshot.lockoutThreshold,
                    "maximum": profile.maximum_lockout_threshold,
                },
                recommendation="Review the lockout threshold against the organization's threat model.",
            )
        )

    if snapshot.machineAccountQuota > profile.maximum_machine_account_quota:
        findings.append(
            Finding(
                id="AD-MACHINE-ACCOUNT-QUOTA",
                severity=Severity.MEDIUM,
                title="Authenticated users may create more machine accounts than the baseline allows",
                evidence={
                    "configured": snapshot.machineAccountQuota,
                    "maximum": profile.maximum_machine_account_quota,
                },
                recommendation=(
                    "Set machine-account creation to an explicitly delegated workflow and reduce "
                    "ms-DS-MachineAccountQuota where compatible with provisioning processes."
                ),
            )
        )

    if not snapshot.recycleBinEnabled:
        findings.append(
            Finding(
                id="AD-RECYCLE-BIN",
                severity=Severity.MEDIUM,
                title="Active Directory Recycle Bin is not enabled",
                evidence={"recycleBinEnabled": False},
                recommendation=(
                    "Evaluate enabling Active Directory Recycle Bin to improve recovery from "
                    "accidental directory-object deletion."
                ),
            )
        )

    if snapshot.domainMode in _LEGACY_DOMAIN_MODES:
        findings.append(
            Finding(
                id="AD-DOMAIN-FUNCTIONAL-LEVEL",
                severity=Severity.LOW,
                title="Domain functional level is older than Windows Server 2016",
                evidence={"domainMode": snapshot.domainMode},
                recommendation=(
                    "Validate domain-controller compatibility and plan a supported functional-level "
                    "upgrade when the environment permits it."
                ),
            )
        )

    return BaselineReport(
        compliant=not findings,
        profile=profile,
        snapshot=snapshot,
        findings=findings,
    )
