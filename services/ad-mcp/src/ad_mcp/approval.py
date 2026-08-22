from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ApprovalChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1, le=1)
    operation: str = Field(min_length=1, max_length=200)
    correlation_id: UUID
    idempotency_key: str = Field(min_length=8, max_length=128)
    issued_at: datetime
    expires_at: datetime
    parameters: dict[str, Any]
    pre_state: dict[str, Any]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> ApprovalChallenge:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval challenge must expire after it is issued")
        return self


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def encode_challenge(challenge: ApprovalChallenge) -> str:
    raw = _canonical_json(challenge.model_dump(mode="json"))
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_challenge(encoded: str) -> ApprovalChallenge:
    encoded = encoded.strip()
    if not encoded or len(encoded) > 32768:
        raise ValueError("approval_challenge is empty or too large")
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("approval_challenge is not valid canonical challenge data") from exc
    return ApprovalChallenge.model_validate(value)


def create_challenge(
    *,
    operation: str,
    correlation_id: UUID,
    idempotency_key: str,
    parameters: dict[str, Any],
    pre_state: dict[str, Any],
    ttl_seconds: int,
    now: datetime | None = None,
) -> tuple[str, ApprovalChallenge]:
    issued_at = now or datetime.now(timezone.utc)
    challenge = ApprovalChallenge(
        operation=operation,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
        parameters=parameters,
        pre_state=pre_state,
    )
    return encode_challenge(challenge), challenge


def build_approval_signature(secret: str, challenge: str, approved_by: str) -> str:
    """Build the HMAC used by an external approval workflow.

    This helper is intentionally not exposed as an MCP tool. The shared secret
    belongs in the approval system (for example an n8n credential) and in the
    AD MCP runtime, never in model-visible arguments or repository config.
    """

    if len(secret) < 32:
        raise ValueError("approval HMAC secret must be at least 32 characters")
    approved_by = approved_by.strip()
    if not approved_by:
        raise ValueError("approved_by must not be blank")
    message = f"{challenge}\n{approved_by}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_approval(
    *,
    secret: str,
    challenge: str,
    approved_by: str,
    signature: str,
    expected_operation: str,
    now: datetime | None = None,
) -> ApprovalChallenge:
    parsed = decode_challenge(challenge)
    if parsed.operation != expected_operation:
        raise ValueError("approval challenge is for a different operation")
    current = now or datetime.now(timezone.utc)
    if current > parsed.expires_at:
        raise ValueError("approval challenge has expired")
    expected = build_approval_signature(secret, challenge, approved_by)
    if not hmac.compare_digest(expected, signature.strip().casefold()):
        raise ValueError("approval signature is invalid")
    return parsed
