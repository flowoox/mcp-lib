from __future__ import annotations

import re
from typing import Any

from mcp_common.operations import (
    Approval,
    ApprovalState,
    AuditEvent,
    ChangePlan,
    ChangeStep,
    OperationPhase,
    OperationStatus,
    RiskLevel,
    Verification,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .changes import clean_idempotency_key, operation_context

_SAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")
_UPN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._'+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")


class DisabledUserFields(BaseModel):
    """Narrow non-secret attributes accepted by disabled-user provisioning."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    sam_account_name: str = Field(min_length=1, max_length=20)
    user_principal_name: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=256)
    ou_dn: str = Field(min_length=4, max_length=1024)
    given_name: str | None = Field(default=None, max_length=64)
    surname: str | None = Field(default=None, max_length=64)
    mail: str | None = Field(default=None, max_length=320)
    employee_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=1024)

    @field_validator("name", "display_name")
    @classmethod
    def clean_required_text(cls, value: str) -> str:
        return _clean_text(value, required=True)

    @field_validator("given_name", "surname", "employee_id", "description")
    @classmethod
    def clean_optional_text(cls, value: str | None) -> str | None:
        return _clean_optional(value)

    @field_validator("sam_account_name")
    @classmethod
    def validate_sam_account_name(cls, value: str) -> str:
        value = value.strip()
        if not _SAM_RE.fullmatch(value):
            raise ValueError(
                "sam_account_name must be 1-20 characters using letters, digits, '.', '_', or '-'"
            )
        return value

    @field_validator("user_principal_name")
    @classmethod
    def validate_upn(cls, value: str) -> str:
        return _clean_principal(value, field_name="user_principal_name")

    @field_validator("mail")
    @classmethod
    def validate_mail(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return _clean_principal(value, field_name="mail")

    @field_validator("ou_dn")
    @classmethod
    def validate_ou_dn(cls, value: str) -> str:
        value = _clean_text(value, required=True)
        if not value.upper().startswith("OU="):
            raise ValueError("ou_dn must identify an Organizational Unit and start with 'OU='")
        return value

    def directory_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "samAccountName": self.sam_account_name,
            "userPrincipalName": self.user_principal_name,
            "displayName": self.display_name,
            "ouDn": self.ou_dn,
            "givenName": self.given_name,
            "surname": self.surname,
            "mail": self.mail,
            "employeeId": self.employee_id,
            "description": self.description,
        }

    def approval_intent(self) -> dict[str, Any]:
        return {**self.directory_payload(), "enabled": False}


class DisabledUserPlanRequest(DisabledUserFields):
    idempotency_key: str = Field(min_length=8, max_length=128)

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        return clean_idempotency_key(value)


class DisabledUserChangeRequest(DisabledUserPlanRequest):
    approval_grant: str = Field(min_length=16, max_length=8192)


def _clean_text(value: str, *, required: bool) -> str:
    value = value.strip()
    if required and not value:
        raise ValueError("value must not be blank")
    if any(ord(character) < 32 for character in value):
        raise ValueError("value must not contain control characters")
    return value


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    value = _clean_text(value, required=False)
    return value or None


def _clean_principal(value: str, *, field_name: str) -> str:
    value = value.strip()
    if not _UPN_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a conservative user@dns-suffix value")
    return value


def disabled_user_target(sam_account_name: str) -> str:
    value = sam_account_name.strip()
    if not _SAM_RE.fullmatch(value):
        raise ValueError("invalid sam_account_name")
    return f"user:sam:{value}"


def _eq(left: object, right: object) -> bool:
    return str(left or "").casefold() == str(right or "").casefold()


def _optional_eq(requested: str | None, actual: object) -> bool:
    return requested is None or _eq(requested, actual)


def _existing_matches(
    existing: dict[str, Any], request: DisabledUserFields, ou_distinguished_name: str
) -> bool:
    distinguished_name = str(existing.get("distinguishedName") or "")
    in_ou = distinguished_name.casefold().endswith("," + ou_distinguished_name.casefold())
    return all(
        (
            _eq(existing.get("name"), request.name),
            _eq(existing.get("samAccountName"), request.sam_account_name),
            _eq(existing.get("userPrincipalName"), request.user_principal_name),
            _eq(existing.get("displayName"), request.display_name),
            _optional_eq(request.given_name, existing.get("givenName")),
            _optional_eq(request.surname, existing.get("surname")),
            _optional_eq(request.mail, existing.get("mail")),
            _optional_eq(request.employee_id, existing.get("employeeId")),
            _optional_eq(request.description, existing.get("description")),
            in_ou,
            existing.get("enabled") is False,
        )
    )


def analyze_preflight(
    preflight: dict[str, Any], request: DisabledUserFields
) -> tuple[bool, list[str], dict[str, Any] | None]:
    """Return (already_satisfied, conflicts, existing_user) from a static AD preflight."""

    sam_matches = [item for item in preflight.get("samMatches", []) if isinstance(item, dict)]
    upn_matches = [item for item in preflight.get("upnMatches", []) if isinstance(item, dict)]
    ou_dn = str(preflight.get("ouDistinguishedName") or request.ou_dn)
    conflicts: list[str] = []
    if len(sam_matches) > 1:
        conflicts.append("multiple users match the requested sAMAccountName")
        return False, conflicts, None

    existing = sam_matches[0] if sam_matches else None
    existing_guid = str(existing.get("objectGuid")) if existing else None
    upn_conflicts = [
        item
        for item in upn_matches
        if existing_guid is None or str(item.get("objectGuid")) != existing_guid
    ]
    if upn_conflicts:
        conflicts.append("requested userPrincipalName is assigned to another user")

    if existing is not None and not _existing_matches(existing, request, ou_dn):
        conflicts.append("existing sAMAccountName does not match the requested provisioning intent")

    already_satisfied = existing is not None and not conflicts
    return already_satisfied, conflicts, existing


def build_disabled_user_plan(
    *,
    request: DisabledUserPlanRequest,
    preflight: dict[str, Any],
    correlation_id: str,
) -> dict[str, Any]:
    already_satisfied, conflicts, existing = analyze_preflight(preflight, request)
    if conflicts:
        raise ValueError("AD provisioning preflight rejected: " + "; ".join(conflicts))

    context = operation_context(correlation_id, idempotency_key=request.idempotency_key)
    operation = "ad.user.provision-disabled.change"
    target = disabled_user_target(request.sam_account_name)
    plan = ChangePlan(
        operation=operation,
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="ensure-disabled-user-exists",
                target=target,
                reversible=False,
            )
        ],
        pre_state={
            "exists": existing is not None,
            "objectGuid": existing.get("objectGuid") if existing else None,
            "distinguishedName": existing.get("distinguishedName") if existing else None,
        },
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason="Creating a directory identity changes the authoritative identity store and requires approval.",
        ),
    )
    audit = AuditEvent(
        operation="ad.user.provision-disabled.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={"alreadySatisfied": already_satisfied, "enabled": False},
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "approvalBinding": {
            "operation": operation,
            "target": target,
            "idempotencyKey": context.idempotency_key,
            "intent": request.approval_intent(),
        },
        "audit": audit.model_dump(mode="json"),
        "alreadySatisfied": already_satisfied,
    }


def provisioning_verification(
    *, preflight: dict[str, Any], request: DisabledUserFields
) -> Verification:
    already_satisfied, conflicts, existing = analyze_preflight(preflight, request)
    details = {
        "expectedEnabled": False,
        "observedObjectGuid": existing.get("objectGuid") if existing else None,
        "observedDistinguishedName": existing.get("distinguishedName") if existing else None,
        "conflicts": conflicts,
    }
    return Verification(
        check="disabled user exists and matches the approved provisioning intent",
        passed=already_satisfied and not conflicts,
        details=details,
    )
