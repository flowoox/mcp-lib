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


def _preflight(
    request: DisabledUserPlanRequest, existing: dict[str, object] | None = None
) -> dict[str, object]:
    matches = [] if existing is None else [existing]
    return {
        "ouDistinguishedName": request.ou_dn,
        "samMatches": matches,
        "upnMatches": matches,
    }


def test_provisioning_fields_are_narrow_and_never_accept_password_material() -> None:
    request = _request()
    payload = request.directory_payload()
    assert payload["samAccountName"] == "alice.example"
    assert request.approval_intent()["enabled"] is False
    assert not any(
        "password" in key.casefold() for key in DisabledUserPlanRequest.model_fields
    )

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
    preflight = _preflight(request, existing)
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
    preflight = _preflight(request, mismatched)
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


def test_preflight_shape_is_validated_fail_closed() -> None:
    request = _request()
    malformed_payloads = (
        {},
        {"ouDistinguishedName": request.ou_dn, "samMatches": {}, "upnMatches": []},
        {
            "ouDistinguishedName": request.ou_dn,
            "samMatches": [{"samAccountName": request.sam_account_name}],
            "upnMatches": [],
        },
        {
            "ouDistinguishedName": "OU=Other,DC=example,DC=local",
            "samMatches": [],
            "upnMatches": [],
        },
    )
    for preflight in malformed_payloads:
        satisfied, conflicts, _ = analyze_preflight(preflight, request)
        assert satisfied is False
        assert conflicts
        with pytest.raises(ValueError, match="preflight rejected"):
            build_disabled_user_plan(
                request=request,
                preflight=preflight,
                correlation_id="",
            )


def test_omitted_optional_attributes_are_exactly_unset_not_wildcards() -> None:
    request = _request(
        given_name=None,
        surname=None,
        mail=None,
        employee_id=None,
        description=None,
    )
    populated_existing = _existing()
    satisfied, conflicts, _ = analyze_preflight(
        _preflight(request, populated_existing), request
    )
    assert satisfied is False
    assert conflicts

    unset_existing = _existing(
        givenName=None,
        surname=None,
        mail=None,
        employeeId=None,
        description=None,
    )
    satisfied, conflicts, _ = analyze_preflight(_preflight(request, unset_existing), request)
    assert satisfied is True
    assert conflicts == []


def test_existing_user_must_be_directly_in_requested_ou() -> None:
    request = _request()
    nested = _existing(
        distinguishedName="CN=Alice Example,OU=Child,OU=Users,DC=example,DC=local"
    )
    satisfied, conflicts, _ = analyze_preflight(_preflight(request, nested), request)
    assert satisfied is False
    assert conflicts

    escaped_name_request = _request(name="Doe, Alice", display_name="Doe, Alice")
    escaped_name_existing = _existing(
        name="Doe, Alice",
        displayName="Doe, Alice",
        distinguishedName=r"CN=Doe\, Alice,OU=Users,DC=example,DC=local",
    )
    satisfied, conflicts, _ = analyze_preflight(
        _preflight(escaped_name_request, escaped_name_existing), escaped_name_request
    )
    assert satisfied is True
    assert conflicts == []


def test_provisioning_verification_requires_exact_disabled_readback() -> None:
    request = _request()
    exact = _existing()
    verification = provisioning_verification(
        preflight=_preflight(request, exact),
        request=request,
    )
    assert verification.passed is True
    assert verification.details["observedObjectGuid"] == "guid-1"

    enabled = _existing(enabled=True)
    failed = provisioning_verification(
        preflight=_preflight(request, enabled),
        request=request,
    )
    assert failed.passed is False
    assert failed.details["conflicts"]


def test_target_is_stable_and_does_not_include_private_topology() -> None:
    assert disabled_user_target("alice.example") == "user:sam:alice.example"
