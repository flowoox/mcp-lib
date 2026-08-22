import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_common.secret_refs import (
    SecretReferenceEnvelope,
    consume_secret_reference,
    new_secret_reference,
    parse_secret_reference,
    secret_reference_sha256,
    stage_secret_reference,
)
from pydantic import SecretStr, ValidationError


def _secure_dir(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    return root


def test_reference_is_opaque_and_path_safe() -> None:
    reference = new_secret_reference()
    token = parse_secret_reference(reference)
    assert reference.startswith("mcpsecret:v1:")
    assert "/" not in token
    assert "\\" not in token
    assert len(secret_reference_sha256(reference)) == 64

    for value in ("", "../secret", "mcpsecret:v1:../secret", "file:///tmp/secret"):
        with pytest.raises(ValueError, match="invalid opaque secret reference"):
            parse_secret_reference(value)


def test_stage_and_consume_is_one_time_and_target_bound(tmp_path: Path) -> None:
    root = _secure_dir(tmp_path)
    reference = stage_secret_reference(
        root,
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password",
        secret="NotReturned-To-The-Model!",
    )
    token = parse_secret_reference(reference)
    staged = root / f"{token}.json"
    assert staged.exists()
    if os.name != "nt":
        assert staged.stat().st_mode & 0o077 == 0

    secret = consume_secret_reference(
        root,
        reference,
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password",
    )
    assert isinstance(secret, SecretStr)
    assert secret.get_secret_value() == "NotReturned-To-The-Model!"
    assert "NotReturned" not in repr(secret)
    assert not staged.exists()

    with pytest.raises(ValueError, match="already consumed"):
        consume_secret_reference(
            root,
            reference,
            purpose="ad.password-bootstrap",
            target="user:guid:11111111-1111-1111-1111-111111111111",
            idempotency_key="joiner/alice/password",
        )


def test_binding_mismatch_consumes_file_without_exposing_secret(tmp_path: Path) -> None:
    root = _secure_dir(tmp_path)
    reference = stage_secret_reference(
        root,
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password",
        secret="Sensitive-Value",
    )
    token = parse_secret_reference(reference)
    with pytest.raises(ValueError, match="does not match") as error:
        consume_secret_reference(
            root,
            reference,
            purpose="ad.password-bootstrap",
            target="user:guid:22222222-2222-2222-2222-222222222222",
            idempotency_key="joiner/alice/password",
        )
    assert "Sensitive-Value" not in str(error.value)
    assert not (root / f"{token}.json").exists()


def test_expired_or_tampered_envelope_fails_closed(tmp_path: Path) -> None:
    root = _secure_dir(tmp_path)
    now = datetime(2026, 8, 22, tzinfo=timezone.utc)
    reference = stage_secret_reference(
        root,
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password",
        secret="Sensitive-Value",
        ttl_seconds=60,
        now=now,
    )
    with pytest.raises(ValueError, match="expired"):
        consume_secret_reference(
            root,
            reference,
            purpose="ad.password-bootstrap",
            target="user:guid:11111111-1111-1111-1111-111111111111",
            idempotency_key="joiner/alice/password",
            now=now + timedelta(minutes=2),
        )

    reference = stage_secret_reference(
        root,
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password-2",
        secret="Sensitive-Value",
        now=now,
    )
    path = root / f"{parse_secret_reference(reference)}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["reference_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="does not match"):
        consume_secret_reference(
            root,
            reference,
            purpose="ad.password-bootstrap",
            target="user:guid:11111111-1111-1111-1111-111111111111",
            idempotency_key="joiner/alice/password-2",
            now=now,
        )


def test_envelope_never_serializes_plaintext_by_default() -> None:
    now = datetime.now(timezone.utc)
    envelope = SecretReferenceEnvelope(
        purpose="ad.password-bootstrap",
        target="user:guid:11111111-1111-1111-1111-111111111111",
        idempotency_key="joiner/alice/password",
        reference_sha256="a" * 64,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        secret="Sensitive-Value",
    )
    assert "Sensitive-Value" not in repr(envelope)
    assert "Sensitive-Value" not in envelope.model_dump_json()
    assert envelope.model_dump(mode="json")["secret"] == "**********"

    with pytest.raises(ValidationError):
        SecretReferenceEnvelope(
            purpose="ad.password-bootstrap",
            target="user:guid:11111111-1111-1111-1111-111111111111",
            idempotency_key="bad key",
            reference_sha256="a" * 64,
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
            secret="Sensitive-Value",
        )


def test_symlink_secret_file_is_rejected_and_removed(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    root = _secure_dir(tmp_path)
    reference = new_secret_reference()
    token = parse_secret_reference(reference)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    os.chmod(outside, 0o600)
    link = root / f"{token}.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation not permitted")

    with pytest.raises(PermissionError, match="non-link"):
        consume_secret_reference(
            root,
            reference,
            purpose="ad.password-bootstrap",
            target="user:guid:11111111-1111-1111-1111-111111111111",
            idempotency_key="joiner/alice/password",
        )
    assert outside.exists()
