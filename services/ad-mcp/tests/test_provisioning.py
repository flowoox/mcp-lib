import pytest
from pydantic import ValidationError

from ad_mcp.provisioning import (
    DisabledUserFields,
    DisabledUserPlanRequest,
    analyze_preflight,
    build_disabled_user_plan,
    disabled_user_target,
    provisioning_verification,
)


def _request(**overrides: object) -> DisabledUserPlanRequest:
    values = {
        "name": "Alice Example",
        "sam_account_name": "alice.example",
        "user_principal_name": "alice.example@example.local",
        "display_name": "Alice Example",
        "ou_dn": "OU=Users,DC=example,DC=local",
        "given_name": "Alice",
        "surname": "Example",
        "mail": "alice@example.com",
        "employee_id": "E-1001",
        "description": "Provisioned joiner",
        "idempotency_key": "joiner/alice/provision",
    }
    values.update(overrides)
    return DisabledUserPlanRequest(**values)  # type: ignore[arg-type]


def _existing(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "objectGuid": "guid-1",
        "name": "Alice Example",
        "samAccountName": "alice.example",
        "userPrincipalName": "alice.example@example.local",
        "displayName": "Alice Example",
        "givenName": "Alice",
        "surname": "Example",
        "mail": "alice@example.com",
        "employeeId": "E-1001",
        "description": "Provisioned joiner",
        "distinguishedName": "CN=Alice Example,OU=Users,DC=example,DC=local",
        "enabled": False,
    }
    values.update(overrides)
    return values


def test_provisioning_fields_are_narrow_and_never_accept_password_material() -> None:
    request = _request()
    payload = request.directory_payload()
    assert payload["samAccountName"] == "alice.example"
    assert request.approval_intent()["enabled"] is False
    assert not any("password" in key.casefold() for key in request.model_fields)

    with pytest.raises(ValidationError, match="extra_forbidden"):
        DisabledUserFields(
            name="Alice",
            sam_account_name="alice",
            user_principal_name="alice@example.local",
            display_name="Alice",
            ou_dn="OU=Users,DC=example,DC=local",
            password="Secret123!",  # type: ignore[call-arg]
        )


def test_identifiers_and_ou_are_conservatively_validated() -> None:
    with pytest.raises(ValidationError, match="sam_account_name"):
        _request(sam_account_name="alice example")
    with pytest.raises(ValidationError, match="user_principal_name"):
        _request(user_principal_name="not a principal")
    with pytest.raises(ValidationError, match="ou_dn"):
        _request(ou_dn="CN=Users,DC=example,DC=local")
    with pytest.raises(ValidationError, match="idempotency_key"):
        _request(idempotency_key="bad key!")


def test_preflight_marks_exact_disabled_user_as_idempotently_satisfied() -> None:
    request = _request()
    existing = _existing()
    preflight = {
        "ouDistinguishedName": request.ou_dn,
        "samMatches": [existing],
        "upnMatches": [existing],
    }
    satisfied, conflicts, observed = analyze_preflight(preflight, request)
    assert satisfied is True
    assert conflicts == []
    assert observed == existing

    plan = build_disabled_user_plan(
        request=request,
        preflight=preflight,
        correlation_id="",
    )
    assert plan["alreadySatisfied"] is True
    assert plan["plan"]["pre_state"]["objectGuid"] == "guid-1"
    assert plan["plan"]["steps"][0]["reversible"] is False
    assert plan["approvalBinding"]["target"] == "user:sam:alice.example"
    assert plan["approvalBinding"]["intent"]["enabled"] is False


def test_preflight_rejects_sam_or_upn_collision_instead_of_modifying_existing_user() -> None:
    request = _request()
    mismatched = _existing(displayName="Different Person")
    preflight = {
        "ouDistinguishedName": request.ou_dn,
        "samMatches": [mismatched],
        "upnMatches": [mismatched],
    }
    satisfied, conflicts, _ = analyze_preflight(preflight, request)
    assert satisfied is False
    assert any("sAMAccountName" in conflict for conflict in conflicts)
    with pytest.raises(ValueError, match="preflight rejected"):
        build_disabled_user_plan(request=request, preflight=preflight, correlation_id="")

    other = _existing(
        objectGuid="guid-2",
        samAccountName="someone.else",
        distinguishedName="CN=Someone Else,OU=Users,DC=example,DC=local",
    )
    preflight = {
        "ouDistinguishedName": request.ou_dn,
        "samMatches": [],
        "upnMatches": [other],
    }
    _, conflicts, _ = analyze_preflight(preflight, request)
    assert any("userPrincipalName" in conflict for conflict in conflicts)


def test_provisioning_verification_requires_exact_disabled_readback() -> None:
    request = _request()
    exact = _existing()
    verification = provisioning_verification(
        preflight={
            "ouDistinguishedName": request.ou_dn,
            "samMatches": [exact],
            "upnMatches": [exact],
        },
        request=request,
    )
    assert verification.passed is True
    assert verification.details["observedObjectGuid"] == "guid-1"

    enabled = _existing(enabled=True)
    failed = provisioning_verification(
        preflight={
            "ouDistinguishedName": request.ou_dn,
            "samMatches": [enabled],
            "upnMatches": [enabled],
        },
        request=request,
    )
    assert failed.passed is False
    assert failed.details["conflicts"]


def test_target_is_stable_and_does_not_include_private_topology() -> None:
    assert disabled_user_target("alice.example") == "user:sam:alice.example"
