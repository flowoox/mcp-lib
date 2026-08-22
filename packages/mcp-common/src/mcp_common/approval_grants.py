from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .operations import Approval, ApprovalState

_MAX_TTL = timedelta(hours=1)
_CLOCK_SKEW = timedelta(minutes=2)


class ApprovalGrantPayload(BaseModel):
    """Signed, short-lived approval metadata bound to one exact mutation."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    operation: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=128)
    intent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approver: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval grant timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_window(self) -> ApprovalGrantPayload:
        if self.version != 1:
            raise ValueError("unsupported approval grant version")
        if self.expires_at <= self.issued_at:
            raise ValueError("approval grant must expire after it is issued")
        if self.expires_at - self.issued_at > _MAX_TTL:
            raise ValueError("approval grant TTL must not exceed one hour")
        return self


def _secret_bytes(secret: str | bytes) -> bytes:
    value = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(value) < 32:
        raise ValueError("approval signing secret must be at least 32 bytes")
    return value


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid approval grant encoding") from exc


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("approval intent must be JSON-serializable") from exc


def approval_intent_sha256(intent: Mapping[str, Any]) -> str:
    """Return the stable digest used to bind approval to exact desired state."""

    return hashlib.sha256(_canonical_json(intent)).hexdigest()


def _payload_bytes(payload: ApprovalGrantPayload) -> bytes:
    data: dict[str, Any] = payload.model_dump(mode="json")
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_approval_grant(
    secret: str | bytes,
    *,
    operation: str,
    target: str,
    idempotency_key: str,
    intent: Mapping[str, Any],
    approver: str,
    reason: str,
    ttl_seconds: int = 900,
    now: datetime | None = None,
) -> str:
    """Create an opaque grant for an out-of-band approval workflow.

    The signer belongs outside the agent-facing MCP service. ``intent`` must
    contain only the non-secret desired-state fields that the approver reviewed.
    Its canonical SHA-256 digest is embedded in the signed grant so changing a
    boolean/action after approval invalidates the grant.
    """

    if ttl_seconds < 1 or ttl_seconds > int(_MAX_TTL.total_seconds()):
        raise ValueError("ttl_seconds must be between 1 and 3600")
    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload = ApprovalGrantPayload(
        operation=operation,
        target=target,
        idempotency_key=idempotency_key,
        intent_sha256=approval_intent_sha256(intent),
        approver=approver,
        reason=reason,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
    )
    body = _payload_bytes(payload)
    signature = hmac.new(_secret_bytes(secret), body, hashlib.sha256).digest()
    return f"v1.{_b64encode(body)}.{_b64encode(signature)}"


def verify_approval_grant(
    grant: str,
    secret: str | bytes,
    *,
    operation: str,
    target: str,
    idempotency_key: str,
    intent: Mapping[str, Any],
    now: datetime | None = None,
) -> Approval:
    """Verify signature, expiry, and exact mutation binding for an approval grant."""

    parts = grant.strip().split(".")
    if len(parts) != 3 or parts[0] != "v1":
        raise ValueError("invalid approval grant format")
    body = _b64decode(parts[1])
    signature = _b64decode(parts[2])
    expected = hmac.new(_secret_bytes(secret), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid approval grant signature")
    try:
        raw = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid approval grant payload") from exc
    payload = ApprovalGrantPayload.model_validate(raw)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if payload.issued_at - _CLOCK_SKEW > current:
        raise ValueError("approval grant is not yet valid")
    if payload.expires_at < current:
        raise ValueError("approval grant has expired")
    expected_fields = {
        "operation": operation,
        "target": target,
        "idempotency_key": idempotency_key,
        "intent_sha256": approval_intent_sha256(intent),
    }
    actual_fields = {
        "operation": payload.operation,
        "target": payload.target,
        "idempotency_key": payload.idempotency_key,
        "intent_sha256": payload.intent_sha256,
    }
    if actual_fields != expected_fields:
        raise ValueError("approval grant does not match the requested mutation")
    return Approval(
        state=ApprovalState.APPROVED,
        approver=payload.approver,
        reason=payload.reason,
        approved_at=payload.issued_at,
    )
