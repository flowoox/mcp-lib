from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from ad_mcp.approval import (
    build_approval_signature,
    create_challenge,
    decode_challenge,
    encode_challenge,
    verify_approval,
)

_SECRET = "0123456789abcdef0123456789abcdef"


def _challenge() -> tuple[str, datetime]:
    now = datetime(2026, 8, 22, 8, 0, tzinfo=timezone.utc)
    encoded, _ = create_challenge(
        operation="ad.user.create-disabled",
        correlation_id=uuid4(),
        idempotency_key="joiner:alice:001",
        parameters={"sam_account_name": "alice"},
        pre_state={"user_exists": False},
        ttl_seconds=900,
        now=now,
    )
    return encoded, now


def test_challenge_round_trip_and_valid_signature() -> None:
    encoded, now = _challenge()
    parsed = decode_challenge(encoded)
    signature = build_approval_signature(_SECRET, encoded, "approver@example.invalid")
    verified = verify_approval(
        secret=_SECRET,
        challenge=encoded,
        approved_by="approver@example.invalid",
        signature=signature,
        expected_operation="ad.user.create-disabled",
        now=now + timedelta(minutes=1),
    )
    assert verified == parsed
    assert parsed.parameters == {"sam_account_name": "alice"}


def test_signature_binds_exact_challenge_and_approver() -> None:
    encoded, now = _challenge()
    signature = build_approval_signature(_SECRET, encoded, "approver@example.invalid")
    parsed = decode_challenge(encoded)
    tampered = encode_challenge(
        parsed.model_copy(update={"parameters": {"sam_account_name": "mallory"}})
    )

    with pytest.raises(ValueError, match="signature"):
        verify_approval(
            secret=_SECRET,
            challenge=tampered,
            approved_by="approver@example.invalid",
            signature=signature,
            expected_operation="ad.user.create-disabled",
            now=now + timedelta(minutes=1),
        )
    with pytest.raises(ValueError, match="signature"):
        verify_approval(
            secret=_SECRET,
            challenge=encoded,
            approved_by="different-approver@example.invalid",
            signature=signature,
            expected_operation="ad.user.create-disabled",
            now=now + timedelta(minutes=1),
        )


def test_expired_and_wrong_operation_are_rejected() -> None:
    encoded, now = _challenge()
    signature = build_approval_signature(_SECRET, encoded, "approver@example.invalid")

    with pytest.raises(ValueError, match="expired"):
        verify_approval(
            secret=_SECRET,
            challenge=encoded,
            approved_by="approver@example.invalid",
            signature=signature,
            expected_operation="ad.user.create-disabled",
            now=now + timedelta(hours=1),
        )
    with pytest.raises(ValueError, match="different operation"):
        verify_approval(
            secret=_SECRET,
            challenge=encoded,
            approved_by="approver@example.invalid",
            signature=signature,
            expected_operation="ad.group.member.add",
            now=now + timedelta(minutes=1),
        )


def test_approval_secret_has_minimum_strength_floor() -> None:
    encoded, _ = _challenge()
    with pytest.raises(ValueError, match="at least 32"):
        build_approval_signature("too-short", encoded, "approver")
