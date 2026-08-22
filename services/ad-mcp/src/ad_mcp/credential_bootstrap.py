from __future__ import annotations

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
from mcp_common.secret_refs import (
    consume_secret_reference,
    parse_secret_reference,
    secret_reference_sha256,
)
from mcp_common.store import AtomicJsonStore
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .changes import clean_idempotency_key, clean_identity, operation_context

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RECEIPT_SCHEMA_VERSION = 2
_SECRET_PURPOSE = "ad.password-bootstrap"


class CredentialBootstrapPlanRequest(BaseModel):
    """Non-secret model-facing request for initial password establishment."""

    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1, max_length=512)
    secret_ref: str = Field(min_length=1, max_length=160)
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
            "secretRefSha256": secret_reference_sha256(self.secret_ref),
            "credentialEstablished": True,
            "enabled": False,
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
    """Consume one purpose-, target-, and idempotency-bound secret envelope."""

    def __init__(self, root: str | Path):
        root_text = str(root).strip()
        if not root_text:
            raise ValueError("AD_CREDENTIAL_SECRET_DIRECTORY must not be blank")
        self.root = Path(root_text).expanduser()

    def consume(
        self,
        secret_ref: str,
        *,
        target: str,
        idempotency_key: str,
    ) -> SecretStr:
        try:
            return consume_secret_reference(
                self.root,
                clean_secret_ref(secret_ref),
                purpose=_SECRET_PURPOSE,
                target=target,
                idempotency_key=clean_idempotency_key(idempotency_key),
            )
        except (OSError, PermissionError, ValueError) as exc:
            raise SecretResolutionError(str(exc)) from exc


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
        return secret_reference_sha256(clean_secret_ref(secret_ref))

    @staticmethod
    def _intent(
        *, object_guid: str, secret_ref: str, pre_password_last_set: str | None
    ) -> dict[str, Any]:
        return {
            "objectGuid": clean_object_guid(object_guid),
            "secretRefDigest": CredentialReceiptStore.secret_ref_digest(secret_ref),
            "prePasswordLastSet": pre_password_last_set,
        }

    def _document(self) -> tuple[dict[str, Any], dict[str, Any]]:
        document = self.store.read()
        if document.get("schemaVersion") != _RECEIPT_SCHEMA_VERSION:
            raise RuntimeError("credential receipt store schema is unsupported")
        receipts = document.get("receipts")
        if not isinstance(receipts, dict):
            raise RuntimeError("credential receipt store is malformed")
        return document, receipts

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        key = clean_idempotency_key(idempotency_key)
        _, receipts = self._document()
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
        pre_password_last_set: str | None,
    ) -> dict[str, Any]:
        key = clean_idempotency_key(idempotency_key)
        expected = self._intent(
            object_guid=object_guid,
            secret_ref=secret_ref,
            pre_password_last_set=pre_password_last_set,
        )
        document, receipts = self._document()
        existing = receipts.get(key)
        if existing is not None:
            if not isinstance(existing, dict):
                raise RuntimeError("credential receipt entry is malformed")
            if not receipt_matches_intent(
                existing,
                object_guid=object_guid,
                secret_ref=secret_ref,
                pre_password_last_set=pre_password_last_set,
            ):
                raise PermissionError(
                    "idempotency key is already bound to a different credential-bootstrap intent"
                )
            return dict(existing)
        receipt = {
            **expected,
            "status": "pending",
            "observedPasswordLastSet": None,
        }
        receipts[key] = receipt
        self.store.write(document)
        return dict(receipt)

    def mark_verified(
        self,
        *,
        idempotency_key: str,
        object_guid: str,
        secret_ref: str,
        observed_password_last_set: str,
    ) -> dict[str, Any]:
        key = clean_idempotency_key(idempotency_key)
        guid = clean_object_guid(object_guid)
        if not observed_password_last_set.strip():
            raise ValueError("observed_password_last_set is required")
        document, receipts = self._document()
        value = receipts.get(key)
        if not isinstance(value, dict):
            raise RuntimeError("credential receipt is missing")
        receipt = dict(value)
        if not receipt_matches_intent(
            receipt,
            object_guid=guid,
            secret_ref=secret_ref,
            pre_password_last_set=receipt.get("prePasswordLastSet"),
        ):
            raise PermissionError("credential receipt intent changed")
        if receipt.get("status") not in {"pending", "verified"}:
            raise RuntimeError("credential receipt status is invalid")
        receipt["status"] = "verified"
        receipt["observedPasswordLastSet"] = observed_password_last_set
        receipts[key] = receipt
        self.store.write(document)
        return dict(receipt)


def clean_secret_ref(value: str) -> str:
    token = parse_secret_reference(value)
    return f"mcpsecret:v1:{token}"


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
    distinguished_name = preflight.get("distinguishedName")
    sam_account_name = preflight.get("samAccountName")
    if not isinstance(object_guid, str):
        raise ValueError("credential preflight did not return objectGuid")
    object_guid = clean_object_guid(object_guid)
    if expected_object_guid is not None and object_guid != clean_object_guid(expected_object_guid):
        raise ValueError("credential preflight objectGuid does not match the approved identity")
    if not isinstance(enabled, bool):
        raise ValueError("credential preflight did not return a boolean enabled state")
    if enabled:
        raise ValueError("credential bootstrap is allowed only while the AD user remains disabled")
    if not isinstance(established, bool):
        raise ValueError("credential preflight did not return credentialEstablished")
    if established:
        if not isinstance(password_last_set, str) or not password_last_set.strip():
            raise ValueError("credential preflight returned inconsistent password evidence")
    elif password_last_set is not None:
        raise ValueError("credential preflight returned inconsistent password evidence")
    if not isinstance(distinguished_name, str) or not distinguished_name.strip():
        raise ValueError("credential preflight did not return distinguishedName")
    if not isinstance(sam_account_name, str) or not sam_account_name.strip():
        raise ValueError("credential preflight did not return samAccountName")
    return {
        "objectGuid": object_guid,
        "enabled": enabled,
        "credentialEstablished": established,
        "passwordLastSet": password_last_set,
        "samAccountName": sam_account_name,
        "userPrincipalName": preflight.get("userPrincipalName"),
        "distinguishedName": distinguished_name,
    }


def receipt_matches_intent(
    receipt: dict[str, Any] | None,
    *,
    object_guid: str,
    secret_ref: str,
    pre_password_last_set: str | None,
) -> bool:
    if receipt is None:
        return False
    expected = {
        "objectGuid": clean_object_guid(object_guid),
        "secretRefDigest": CredentialReceiptStore.secret_ref_digest(secret_ref),
        "prePasswordLastSet": pre_password_last_set,
    }
    return all(
        hmac.compare_digest(str(receipt.get(field, "")), str(value))
        for field, value in expected.items()
    )


def receipt_matches_plan(
    receipt: dict[str, Any] | None,
    *,
    object_guid: str,
    secret_ref: str,
) -> bool:
    return bool(
        receipt is not None
        and receipt.get("status") == "verified"
        and receipt_matches_intent(
            receipt,
            object_guid=object_guid,
            secret_ref=secret_ref,
            pre_password_last_set=receipt.get("prePasswordLastSet"),
        )
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
                action="set-initial-password-from-one-time-secret-reference",
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
            "oneTimeSecretRequired": True,
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
