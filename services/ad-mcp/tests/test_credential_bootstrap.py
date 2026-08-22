from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

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
    receipt_matches_plan,
)

_GUID = "11111111-2222-3333-4444-555555555555"


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
        "secret_ref": "joiner-alice-20260822",
        "idempotency_key": "joiner/alice/credential/001",
    }
    values.update(overrides)
    return CredentialBootstrapPlanRequest(**values)


def test_model_facing_contract_accepts_secret_reference_but_no_password_field() -> None:
    request = _request()
    assert request.secret_ref == "joiner-alice-20260822"
    assert "password" not in CredentialBootstrapPlanRequest.model_fields
    assert "password" not in CredentialBootstrapChangeRequest.model_fields
    with pytest.raises(ValidationError):
        CredentialBootstrapPlanRequest(
            identity="alice",
            secret_ref="joiner-alice-20260822",
            idempotency_key="joiner/alice/credential/001",
            password="must-never-be-model-facing",  # type: ignore[call-arg]
        )


def test_secret_reference_grammar_blocks_paths_and_controlled_escape() -> None:
    assert clean_secret_ref("joiner.alice_2026-08") == "joiner.alice_2026-08"
    for value in ("../secret", "folder/secret", "\\server\\secret", ".", " secret "):
        with pytest.raises(ValueError):
            clean_secret_ref(value)


def test_file_secret_resolver_reads_only_direct_non_symlink_child(tmp_path) -> None:
    root = tmp_path / "secrets"
    root.mkdir()
    secret_value = "Temporary-Password-42!"
    (root / "joiner-alice").write_text(secret_value, encoding="utf-8")
    resolver = FileSecretResolver(root)
    assert resolver.resolve("joiner-alice") == secret_value

    outside = tmp_path / "outside"
    outside.write_text("outside-secret", encoding="utf-8")
    link = root / "linked-secret"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable in this test environment")
    with pytest.raises(SecretResolutionError, match="symbolic links"):
        resolver.resolve("linked-secret")


def test_file_secret_resolver_errors_never_embed_secret_value(tmp_path) -> None:
    root = tmp_path / "secrets"
    root.mkdir()
    (root / "empty").write_bytes(b"")
    resolver = FileSecretResolver(root)
    with pytest.raises(SecretResolutionError) as exc_info:
        resolver.resolve("empty")
    assert "password" not in str(exc_info.value).casefold()


def test_preflight_is_guid_bound_disabled_and_fail_closed() -> None:
    observed = analyze_credential_preflight(_preflight())
    assert observed["objectGuid"] == _GUID
    assert observed["credentialEstablished"] is False

    with pytest.raises(ValueError, match="remains disabled"):
        analyze_credential_preflight(_preflight(enabled=True))
    with pytest.raises(ValueError, match="objectGuid"):
        analyze_credential_preflight(_preflight(object_guid="not-a-guid"))
    malformed = _preflight()
    malformed["credentialEstablished"] = True
    with pytest.raises(ValueError, match="inconsistent"):
        analyze_credential_preflight(malformed)


def test_plan_binds_guid_secret_reference_and_idempotency_without_secret_value() -> None:
    request = _request()
    plan = build_credential_bootstrap_plan(
        request=request,
        preflight=_preflight(),
        correlation_id="",
    )
    binding = plan["approvalBinding"]
    assert binding["target"] == f"user:guid:{_GUID}"
    assert binding["intent"] == {
        "objectGuid": _GUID,
        "secretRef": request.secret_ref,
        "credentialEstablished": True,
    }
    serialized = json.dumps(plan)
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


def test_receipt_store_binds_idempotency_to_guid_reference_and_secret_fingerprint(
    tmp_path,
) -> None:
    path = tmp_path / "receipts.json"
    store = CredentialReceiptStore(path)
    secret = "Temporary-Password-42!"
    fingerprint = store.secret_fingerprint(secret, key="k" * 32)
    receipt = store.prepare(
        idempotency_key="joiner/alice/credential/001",
        object_guid=_GUID,
        secret_ref="joiner-alice",
        secret_fingerprint=fingerprint,
        pre_password_last_set=None,
    )
    assert receipt["status"] == "pending"
    serialized = path.read_text(encoding="utf-8")
    assert secret not in serialized
    assert "joiner-alice" not in serialized

    same = store.prepare(
        idempotency_key="joiner/alice/credential/001",
        object_guid=_GUID,
        secret_ref="joiner-alice",
        secret_fingerprint=fingerprint,
        pre_password_last_set=None,
    )
    assert same == receipt

    with pytest.raises(PermissionError, match="different credential-bootstrap intent"):
        store.prepare(
            idempotency_key="joiner/alice/credential/001",
            object_guid=_GUID,
            secret_ref="joiner-bob",
            secret_fingerprint=fingerprint,
            pre_password_last_set=None,
        )

    verified = store.mark_verified(
        idempotency_key="joiner/alice/credential/001",
        object_guid=_GUID,
        observed_password_last_set="2026-08-22T08:00:00Z",
    )
    assert verified["status"] == "verified"
    assert receipt_matches_plan(
        verified,
        object_guid=_GUID,
        secret_ref="joiner-alice",
    )


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
