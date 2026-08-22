from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from ad_mcp.credential_bootstrap import (
    CredentialBootstrapChangeRequest,
    CredentialBootstrapPlanRequest,
    CredentialReceiptStore,
    FileSecretResolver,
    SecretResolutionError,
    analyze_credential_preflight,
    build_credential_bootstrap_plan,
    clean_secret_ref,
    credential_bootstrap_verification,
    receipt_matches_intent,
    receipt_matches_plan,
)
from mcp_common.secret_refs import (
    parse_secret_reference,
    secret_reference_sha256,
    stage_secret_reference,
)

_GUID = "11111111-2222-3333-4444-555555555555"
_REF = "mcpsecret:v1:" + "A" * 43
_IDEMPOTENCY_KEY = "joiner/alice/credential/001"
_TARGET = f"user:guid:{_GUID}"


def _preflight(
    *,
    enabled: bool = False,
    credential_established: bool = False,
    object_guid: str = _GUID,
) -> dict[str, object]:
    return {
        "objectGuid": object_guid,
        "samAccountName": "alice",
        "userPrincipalName": "alice@example.local",
        "distinguishedName": "CN=Alice,OU=Users,DC=example,DC=local",
        "enabled": enabled,
        "credentialEstablished": credential_established,
        "passwordLastSet": (
            "2026-08-22T08:00:00.0000000Z" if credential_established else None
        ),
    }


def _request(**overrides: str) -> CredentialBootstrapPlanRequest:
    values = {
        "identity": "alice",
        "secret_ref": _REF,
        "idempotency_key": _IDEMPOTENCY_KEY,
    }
    values.update(overrides)
    return CredentialBootstrapPlanRequest(**values)


def _secure_root(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    return root


def _stage(tmp_path: Path, *, target: str = _TARGET) -> tuple[Path, str]:
    root = _secure_root(tmp_path)
    reference = stage_secret_reference(
        root,
        purpose="ad.password-bootstrap",
        target=target,
        idempotency_key=_IDEMPOTENCY_KEY,
        secret="Temporary-Password-42!",
    )
    return root, reference


def test_model_facing_contract_accepts_opaque_reference_but_no_password_field() -> None:
    request = _request()
    assert request.secret_ref == _REF
    assert "password" not in CredentialBootstrapPlanRequest.model_fields
    assert "password" not in CredentialBootstrapChangeRequest.model_fields
    with pytest.raises(ValidationError):
        CredentialBootstrapPlanRequest(
            identity="alice",
            secret_ref=_REF,
            idempotency_key=_IDEMPOTENCY_KEY,
            password="must-never-be-model-facing",  # type: ignore[call-arg]
        )


def test_secret_reference_grammar_requires_versioned_opaque_handle() -> None:
    assert clean_secret_ref(f" {_REF} ") == _REF
    assert parse_secret_reference(_REF) == "A" * 43
    for value in (
        "joiner-alice-20260822",
        "../secret",
        "folder/secret",
        "\\server\\secret",
        "file:///tmp/secret",
        ".",
    ):
        with pytest.raises(ValueError):
            clean_secret_ref(value)


def test_file_secret_resolver_consumes_target_bound_reference_once(tmp_path: Path) -> None:
    root, reference = _stage(tmp_path)
    token = parse_secret_reference(reference)
    secret = FileSecretResolver(root).consume(
        reference,
        target=_TARGET,
        idempotency_key=_IDEMPOTENCY_KEY,
    )
    assert isinstance(secret, SecretStr)
    assert secret.get_secret_value() == "Temporary-Password-42!"
    assert "Temporary-Password" not in repr(secret)
    assert not (root / f"{token}.json").exists()

    with pytest.raises(SecretResolutionError, match="already consumed"):
        FileSecretResolver(root).consume(
            reference,
            target=_TARGET,
            idempotency_key=_IDEMPOTENCY_KEY,
        )


def test_file_secret_resolver_fails_closed_on_binding_mismatch(tmp_path: Path) -> None:
    root, reference = _stage(tmp_path)
    token = parse_secret_reference(reference)
    with pytest.raises(SecretResolutionError, match="does not match") as exc_info:
        FileSecretResolver(root).consume(
            reference,
            target="user:guid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            idempotency_key=_IDEMPOTENCY_KEY,
        )
    assert "Temporary-Password" not in str(exc_info.value)
    assert not (root / f"{token}.json").exists()


def test_preflight_is_guid_bound_disabled_and_fail_closed() -> None:
    observed = analyze_credential_preflight(_preflight())
    assert observed["objectGuid"] == _GUID
    assert observed["credentialEstablished"] is False

    with pytest.raises(ValueError, match="remains disabled"):
        analyze_credential_preflight(_preflight(enabled=True))
    with pytest.raises(ValueError, match="object GUID"):
        analyze_credential_preflight(_preflight(object_guid="not-a-guid"))
    malformed = _preflight()
    malformed["credentialEstablished"] = True
    with pytest.raises(ValueError, match="inconsistent"):
        analyze_credential_preflight(malformed)
    missing_identity = _preflight()
    del missing_identity["distinguishedName"]
    with pytest.raises(ValueError, match="distinguishedName"):
        analyze_credential_preflight(missing_identity)


def test_plan_binds_guid_reference_digest_and_idempotency_without_reference() -> None:
    request = _request()
    plan = build_credential_bootstrap_plan(
        request=request,
        preflight=_preflight(),
        correlation_id="",
    )
    binding = plan["approvalBinding"]
    assert binding["target"] == _TARGET
    assert binding["intent"] == {
        "objectGuid": _GUID,
        "secretRefSha256": secret_reference_sha256(request.secret_ref),
        "credentialEstablished": True,
        "enabled": False,
    }
    serialized = json.dumps(plan)
    assert request.secret_ref not in serialized
    assert "Temporary-Password" not in serialized
    assert plan["alreadySatisfied"] is False
    assert plan["plan"]["pre_state"]["credentialEstablished"] is False


def test_existing_password_state_requires_matching_verified_receipt() -> None:
    request = _request()
    with pytest.raises(ValueError, match="no matching verified bootstrap receipt"):
        build_credential_bootstrap_plan(
            request=request,
            preflight=_preflight(credential_established=True),
            correlation_id="",
        )
    plan = build_credential_bootstrap_plan(
        request=request,
        preflight=_preflight(credential_established=True),
        correlation_id="",
        matching_verified_receipt=True,
    )
    assert plan["alreadySatisfied"] is True


def test_receipt_store_binds_idempotency_without_password_verifier(tmp_path: Path) -> None:
    path = tmp_path / "receipts.json"
    store = CredentialReceiptStore(path)
    receipt = store.prepare(
        idempotency_key=_IDEMPOTENCY_KEY,
        object_guid=_GUID,
        secret_ref=_REF,
        pre_password_last_set=None,
    )
    assert receipt["status"] == "pending"
    serialized = path.read_text(encoding="utf-8")
    assert _REF not in serialized
    assert "Temporary-Password" not in serialized
    assert "secretFingerprint" not in serialized
    assert receipt_matches_intent(
        receipt,
        object_guid=_GUID,
        secret_ref=_REF,
        pre_password_last_set=None,
    )
    assert not receipt_matches_plan(receipt, object_guid=_GUID, secret_ref=_REF)

    same = store.prepare(
        idempotency_key=_IDEMPOTENCY_KEY,
        object_guid=_GUID,
        secret_ref=_REF,
        pre_password_last_set=None,
    )
    assert same == receipt

    other_ref = "mcpsecret:v1:" + "B" * 43
    with pytest.raises(PermissionError, match="different credential-bootstrap intent"):
        store.prepare(
            idempotency_key=_IDEMPOTENCY_KEY,
            object_guid=_GUID,
            secret_ref=other_ref,
            pre_password_last_set=None,
        )

    verified = store.mark_verified(
        idempotency_key=_IDEMPOTENCY_KEY,
        object_guid=_GUID,
        secret_ref=_REF,
        observed_password_last_set="2026-08-22T08:00:00Z",
    )
    assert verified["status"] == "verified"
    assert receipt_matches_plan(verified, object_guid=_GUID, secret_ref=_REF)


def test_legacy_receipt_schema_is_rejected_instead_of_implicitly_migrated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "receipts.json"
    path.write_text('{"schemaVersion":1,"receipts":{}}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="schema is unsupported"):
        CredentialReceiptStore(path).get(_IDEMPOTENCY_KEY)


def test_verification_requires_same_guid_disabled_user_and_password_state() -> None:
    passed = credential_bootstrap_verification(
        preflight=_preflight(credential_established=True),
        expected_object_guid=_GUID,
    )
    assert passed.passed is True

    missing = credential_bootstrap_verification(
        preflight=_preflight(credential_established=False),
        expected_object_guid=_GUID,
    )
    assert missing.passed is False

    wrong_guid = credential_bootstrap_verification(
        preflight=_preflight(
            credential_established=True,
            object_guid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ),
        expected_object_guid=_GUID,
    )
    assert wrong_guid.passed is False
