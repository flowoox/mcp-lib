from datetime import datetime, timedelta, timezone

import pytest
from mcp_common.approval_grants import issue_approval_grant, verify_approval_grant

SECRET = "x" * 32
NOW = datetime(2026, 8, 22, 8, 30, tzinfo=timezone.utc)


def _grant(**overrides: object) -> str:
    values = {
        "operation": "ad.user.enabled.change",
        "target": "user:alice",
        "idempotency_key": "joiner/alice/enable",
        "approver": "change-manager@example.invalid",
        "reason": "Approved joiner workflow",
        "ttl_seconds": 900,
        "now": NOW,
    }
    values.update(overrides)
    return issue_approval_grant(SECRET, **values)  # type: ignore[arg-type]


def test_approval_grant_verifies_exact_mutation_binding() -> None:
    approval = verify_approval_grant(
        _grant(),
        SECRET,
        operation="ad.user.enabled.change",
        target="user:alice",
        idempotency_key="joiner/alice/enable",
        now=NOW + timedelta(minutes=1),
    )
    assert approval.state.value == "approved"
    assert approval.approver == "change-manager@example.invalid"
    assert approval.reason == "Approved joiner workflow"


def test_approval_grant_rejects_replay_for_other_target_or_operation() -> None:
    grant = _grant()
    with pytest.raises(ValueError, match="does not match"):
        verify_approval_grant(
            grant,
            SECRET,
            operation="ad.user.enabled.change",
            target="user:bob",
            idempotency_key="joiner/alice/enable",
            now=NOW,
        )
    with pytest.raises(ValueError, match="does not match"):
        verify_approval_grant(
            grant,
            SECRET,
            operation="ad.user.group-membership.change",
            target="user:alice",
            idempotency_key="joiner/alice/enable",
            now=NOW,
        )


def test_approval_grant_rejects_tamper_and_expiry() -> None:
    grant = _grant()
    prefix, body, signature = grant.split(".")
    tampered = f"{prefix}.{body[:-1]}A.{signature}"
    with pytest.raises(ValueError, match="signature"):
        verify_approval_grant(
            tampered,
            SECRET,
            operation="ad.user.enabled.change",
            target="user:alice",
            idempotency_key="joiner/alice/enable",
            now=NOW,
        )
    with pytest.raises(ValueError, match="expired"):
        verify_approval_grant(
            grant,
            SECRET,
            operation="ad.user.enabled.change",
            target="user:alice",
            idempotency_key="joiner/alice/enable",
            now=NOW + timedelta(minutes=16),
        )


def test_approval_grant_requires_strong_secret_and_short_ttl() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        issue_approval_grant(
            "short",
            operation="x",
            target="y",
            idempotency_key="abcdefgh",
            approver="a",
            reason="r",
            now=NOW,
        )
    with pytest.raises(ValueError, match="3600"):
        _grant(ttl_seconds=3601)
