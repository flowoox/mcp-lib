from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
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
from mcp_common.store import AtomicJsonStore
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .changes import clean_idempotency_key, clean_identity, operation_context

_SECRET_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RECEIPT_SCHEMA_VERSION = 1
_MAX_SECRET_BYTES = 8192


class CredentialBootstrapPlanRequest(BaseModel):
    """Non-secret model-facing request for initial password establishment."""

    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1, max_length=512)
    secret_ref: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128)

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return clean_identity(value)

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str) -> str:
        return clean_secret_ref(value)

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        return clean_idempotency_key(value)

    def approval_intent(self, object_guid: str) -> dict[str, Any]:
        return {
            "objectGuid": clean_object_guid(object_guid),
            "secretRef": self.secret_ref,
            "credentialEstablished": True,
        }


class CredentialBootstrapChangeRequest(CredentialBootstrapPlanRequest):
    expected_object_guid: str = Field(min_length=36, max_length=36)
    approval_grant: str = Field(min_length=16, max_length=8192)

    @field_validator("expected_object_guid")
    @classmethod
    def validate_expected_object_guid(cls, value: str) -> str:
        return clean_object_guid(value)


class SecretResolutionError(RuntimeError):
    """Raised without ever embedding secret material in the exception text."""


class FileSecretResolver:
    """Resolve an opaque reference to one direct child of a configured secret directory.

    The MCP caller supplies only a conservative reference token. It can never
    supply an arbitrary filesystem path. The resolved secret is returned only to
    the internal credential mutation path and must never be included in MCP
    output, audit metadata, command arguments or the JSON payload environment.
    """

    def __init__(self, root: str | Path):
        root_text = str(root).strip()
        if not root_text:
            raise ValueError("AD_CREDENTIAL_SECRET_DIRECTORY must not be blank")
        self.root = Path(root_text).expanduser().resolve()

    def resolve(self, secret_ref: str) -> str:
        reference = clean_secret_ref(secret_ref)
        candidate = self.root / reference
        if candidate.is_symlink():
            raise SecretResolutionError("credential secret references must not be symbolic links")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise SecretResolutionError("credential secret reference is unavailable") from exc
        if resolved.parent != self.root or not resolved.is_file():
            raise SecretResolutionError("credential secret reference escaped the configured directory")
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise SecretResolutionError("credential secret reference could not be read") from exc
        if not raw:
            raise SecretResolutionError("credential secret reference is empty")
        if len(raw) > _MAX_SECRET_BYTES:
            raise SecretResolutionError("credential secret reference exceeds the maximum size")
        try:
            secret = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecretResolutionError("credential secret reference must contain UTF-8 text") from exc
        if "\x00" in secret:
            raise SecretResolutionError("credential secret reference contains an invalid NUL character")
        return secret


class CredentialReceiptStore:
    """Persistent non-secret idempotency receipts for password bootstrap operations."""

    def __init__(self, path: str | Path):
        path_text = str(path).strip()
        if not path_text:
            raise ValueError("AD_CREDENTIAL_RECEIPT_STORE must not be blank")
        self.store = AtomicJsonStore(
            path_text,
            default={"schemaVersion": _RECEIPT_SCHEMA_VERSION, "receipts": {}},
        )

    @staticmethod
    def secret_ref_digest(secret_ref: str) -> str:
        reference = clean_secret_ref(secret_ref)
        return hashlib.sha256(reference.encode("utf-8")).hexdigest()

    @staticmethod
    def secret_fingerprint(secret: str, *, key: str) -> str:
        if not key:
            raise ValueError("credential fingerprint key must not be empty")
        return hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        key = clean_idempotency_key(idempotency_key)
        document = self.store.read()
        receipts = document.get("receipts")
        if not isinstance(receipts, dict):
            raise RuntimeError("credential receipt store is malformed")
        value = receipts.get(key)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise RuntimeError("credential receipt entry is malformed")
        return dict(value)

    def prepare(
        self,
        *,
        idempotency_key: str,
        object_guid: str,
        secret_ref: str,
        secret_fingerprint: str,
        pre_password_last_set: str | None,
    ) -> dict[str, Any]:
        key = clean_idempotency_key(idempotency_key)
        guid = clean_object_guid(object_guid)
        ref_digest = self.secret_ref_digest(secret_ref)
        document = self.store.read()
        receipts = document.setdefault("receipts", {})
        if not isinstance(receipts, dict):
            raise RuntimeError("credential receipt store is malformed")
        existing = receipts.get(key)
        expected = {
            "objectGuid": guid,
            "secretRefDigest": ref_digest,
            "secretFingerprint": secret_fingerprint,
        }
        if existing is not None:
            if not isinstance(existing, dict):
                raise RuntimeError("credential receipt entry is malformed")
            for field, value in expected.items():
                if not hmac.compare_digest(str(existing.get(field, "")), str(value)):
                    raise PermissionError(
                        "idempotency key is already bound to a different credential-bootstrap intent"
                    )
            return dict(existing)
        receipt = {
            **expected,
            "status": "pending",
            "prePasswordLastSet": pre_password_last_set,
            "observedPasswordLastSet": None,
        }
        receipts[key] = receipt
        document["schemaVersion"] = _RECEIPT_SCHEMA_VERSION
        self.store.write(document)
        return dict(receipt)

    def mark_verified(
        self,
        *,
        idempotency_key: str,
        object_guid: str,
        observed_password_last_set: str,
    ) -> dict[str, Any]:
        key = clean_idempotency_key(idempotency_key)
        guid = clean_object_guid(object_guid)
        if not observed_password_last_set:
            raise ValueError("observed_password_last_set is required")
        document = self.store.read()
        receipts = document.get("receipts")
        if not isinstance(receipts, dict) or not isinstance(receipts.get(key), dict):
            raise RuntimeError("credential receipt is missing")
        receipt = dict(receipts[key])
        if not hmac.compare_digest(str(receipt.get("objectGuid", "")), guid):
            raise PermissionError("credential receipt object GUID changed")
        receipt["status"] = "verified"
        receipt["observedPasswordLastSet"] = observed_password_last_set
        receipts[key] = receipt
        self.store.write(document)
        return dict(receipt)


def clean_secret_ref(value: str) -> str:
    value = value.strip()
    if not _SECRET_REF_RE.fullmatch(value):
        raise ValueError(
            "secret_ref must be 1-128 characters using letters, digits, '.', '_', or '-'"
        )
    return value


def clean_object_guid(value: str) -> str:
    value = value.strip()
    if not _GUID_RE.fullmatch(value):
        raise ValueError("object GUID must be a canonical 36-character GUID")
    return value.lower()


def credential_target(object_guid: str) -> str:
    return f"user:guid:{clean_object_guid(object_guid)}"


def analyze_credential_preflight(
    preflight: dict[str, Any], *, expected_object_guid: str | None = None
) -> dict[str, Any]:
    """Validate security-sensitive AD readback and return normalized evidence."""

    object_guid = preflight.get("objectGuid")
    enabled = preflight.get("enabled")
    password_last_set = preflight.get("passwordLastSet")
    established = preflight.get("credentialEstablished")
    if not isinstance(object_guid, str):
        raise ValueError("credential preflight did not return objectGuid")
    object_guid = clean_object_guid(object_guid)
    if expected_object_guid is not None and object_guid != clean_object_guid(expected_object_guid):
        raise ValueError("credential preflight objectGuid does not match the approved identity")
    if not isinstance(enabled, bool):
        raise ValueError("credential preflight did not return a boolean enabled state")
    if enabled:
        raise ValueError("credential bootstrap is allowed only while the AD user remains disabled")
    if password_last_set is not None and not isinstance(password_last_set, str):
        raise ValueError("credential preflight returned malformed passwordLastSet evidence")
    if not isinstance(established, bool):
        raise ValueError("credential preflight did not return credentialEstablished")
    if established != bool(password_last_set):
        raise ValueError("credential preflight returned inconsistent password evidence")
    return {
        "objectGuid": object_guid,
        "enabled": enabled,
        "credentialEstablished": established,
        "passwordLastSet": password_last_set,
        "samAccountName": preflight.get("samAccountName"),
        "userPrincipalName": preflight.get("userPrincipalName"),
        "distinguishedName": preflight.get("distinguishedName"),
    }


def receipt_matches_plan(
    receipt: dict[str, Any] | None,
    *,
    object_guid: str,
    secret_ref: str,
) -> bool:
    if receipt is None or receipt.get("status") != "verified":
        return False
    return hmac.compare_digest(
        str(receipt.get("objectGuid", "")), clean_object_guid(object_guid)
    ) and hmac.compare_digest(
        str(receipt.get("secretRefDigest", "")), CredentialReceiptStore.secret_ref_digest(secret_ref)
    )


def build_credential_bootstrap_plan(
    *,
    request: CredentialBootstrapPlanRequest,
    preflight: dict[str, Any],
    correlation_id: str,
    matching_verified_receipt: bool = False,
) -> dict[str, Any]:
    observed = analyze_credential_preflight(preflight)
    if observed["credentialEstablished"] and not matching_verified_receipt:
        raise ValueError(
            "AD user already has credential state but no matching verified bootstrap receipt; refusing an implicit password reset"
        )
    if matching_verified_receipt and not observed["credentialEstablished"]:
        raise ValueError("verified bootstrap receipt conflicts with current AD password state")

    context = operation_context(correlation_id, idempotency_key=request.idempotency_key)
    object_guid = observed["objectGuid"]
    target = credential_target(object_guid)
    operation = "ad.user.credential-bootstrap.change"
    plan = ChangePlan(
        operation=operation,
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="set-initial-password-from-opaque-secret-reference",
                target=target,
                reversible=False,
            )
        ],
        pre_state={
            "objectGuid": object_guid,
            "enabled": False,
            "credentialEstablished": observed["credentialEstablished"],
            "passwordLastSet": observed["passwordLastSet"],
        },
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason="Establishing an AD credential changes authentication material and requires approval.",
        ),
    )
    audit = AuditEvent(
        operation="ad.user.credential-bootstrap.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={
            "credentialEstablished": observed["credentialEstablished"],
            "secretValueExposed": False,
        },
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "expectedObjectGuid": object_guid,
        "approvalBinding": {
            "operation": operation,
            "target": target,
            "idempotencyKey": context.idempotency_key,
            "intent": request.approval_intent(object_guid),
        },
        "audit": audit.model_dump(mode="json"),
        "alreadySatisfied": matching_verified_receipt and observed["credentialEstablished"],
    }


def credential_bootstrap_verification(
    *,
    preflight: dict[str, Any],
    expected_object_guid: str,
) -> Verification:
    try:
        observed = analyze_credential_preflight(
            preflight, expected_object_guid=expected_object_guid
        )
        passed = bool(observed["credentialEstablished"]) and observed["enabled"] is False
        details = {
            "expectedObjectGuid": clean_object_guid(expected_object_guid),
            "observedObjectGuid": observed["objectGuid"],
            "credentialEstablished": observed["credentialEstablished"],
            "enabled": observed["enabled"],
            "passwordLastSet": observed["passwordLastSet"],
        }
    except ValueError as exc:
        passed = False
        details = {
            "expectedObjectGuid": clean_object_guid(expected_object_guid),
            "verificationError": str(exc),
        }
    return Verification(
        check="AD user remains disabled and has independently observed credential state",
        passed=passed,
        details=details,
    )
