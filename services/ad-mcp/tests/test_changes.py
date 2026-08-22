from uuid import uuid4

import pytest
from mcp_common.approval_grants import issue_approval_grant
from mcp_common.operations import ApprovalState, Verification
from pydantic import ValidationError

from ad_mcp.changes import (
    GroupMembershipRequest,
    UserEnabledRequest,
    authorize_change,
    build_group_membership_plan,
    build_user_enabled_plan,
    change_response,
    group_membership_target,
    user_enabled_target,
)
from ad_mcp.config import Settings

SECRET = "approval-secret-which-is-at-least-32-bytes"


def test_user_enabled_plan_captures_prestate_and_requires_approval() -> None:
    correlation_id = str(uuid4())
    result = build_user_enabled_plan(
        identity="alice",
        enabled=False,
        current={"enabled": True, "objectGuid": "guid-1", "passwordLastSet": None},
        correlation_id=correlation_id,
        idempotency_key="offboard/alice/disable",
    )
    plan = result["plan"]
    assert plan["pre_state"] == {
        "enabled": True,
        "objectGuid": "guid-1",
        "credentialEstablished": False,
    }
    assert plan["approval"]["state"] == "required"
    assert plan["risk"] == "high"
    assert plan["steps"][0]["rollback_action"] == "restore enabled=true"
    assert result["approvalBinding"]["intent"] == {"enabled": False}
    assert result["alreadySatisfied"] is False
    assert result["audit"]["context"]["correlation_id"] == correlation_id


def test_user_enable_plan_requires_independent_credential_evidence() -> None:
    with pytest.raises(ValueError, match="credential is established"):
        build_user_enabled_plan(
            identity="alice",
            enabled=True,
            current={"enabled": False, "objectGuid": "guid-1", "passwordLastSet": None},
            correlation_id="",
            idempotency_key="joiner/alice/enable",
        )

    result = build_user_enabled_plan(
        identity="alice",
        enabled=True,
        current={
            "enabled": False,
            "objectGuid": "guid-1",
            "passwordLastSet": "2026-08-22T08:00:00Z",
        },
        correlation_id="",
        idempotency_key="joiner/alice/enable",
    )
    assert result["plan"]["pre_state"]["credentialEstablished"] is True
    assert result["audit"]["metadata"]["credentialEstablished"] is True


def test_group_membership_plan_is_target_state_idempotent() -> None:
    result = build_group_membership_plan(
        user_identity="alice",
        group_identity="VPN-Users",
        present=True,
        current_present=True,
        correlation_id="",
        idempotency_key="joiner/alice/vpn-membership",
    )
    assert result["alreadySatisfied"] is True
    assert result["plan"]["pre_state"] == {"present": True}
    assert result["plan"]["approval"]["state"] == "required"
    assert result["approvalBinding"] == {
        "operation": "ad.user.group-membership.change",
        "target": "user:alice|group:VPN-Users",
        "idempotencyKey": "joiner/alice/vpn-membership",
        "intent": {"present": True},
    }


def test_signed_grant_is_bound_to_exact_ad_target_state_and_idempotency_key() -> None:
    target = user_enabled_target("alice")
    grant = issue_approval_grant(
        SECRET,
        operation="ad.user.enabled.change",
        target=target,
        idempotency_key="joiner/alice/enable",
        intent={"enabled": True},
        approver="change-manager",
        reason="approved onboarding",
    )
    approval = authorize_change(
        grant=grant,
        secret=SECRET,
        operation="ad.user.enabled.change",
        target=target,
        idempotency_key="joiner/alice/enable",
        intent={"enabled": True},
    )
    assert approval.state == ApprovalState.APPROVED
    with pytest.raises(ValueError, match="does not match"):
        authorize_change(
            grant=grant,
            secret=SECRET,
            operation="ad.user.enabled.change",
            target=user_enabled_target("bob"),
            idempotency_key="joiner/alice/enable",
            intent={"enabled": True},
        )
    with pytest.raises(ValueError, match="does not match"):
        authorize_change(
            grant=grant,
            secret=SECRET,
            operation="ad.user.enabled.change",
            target=target,
            idempotency_key="joiner/alice/enable",
            intent={"enabled": False},
        )


def test_change_response_never_contains_approval_grant() -> None:
    target = group_membership_target("alice", "VPN-Users")
    grant = issue_approval_grant(
        SECRET,
        operation="ad.user.group-membership.change",
        target=target,
        idempotency_key="joiner/alice/vpn-membership",
        intent={"present": True},
        approver="change-manager",
        reason="approved onboarding",
    )
    approval = authorize_change(
        grant=grant,
        secret=SECRET,
        operation="ad.user.group-membership.change",
        target=target,
        idempotency_key="joiner/alice/vpn-membership",
        intent={"present": True},
    )
    response = change_response(
        operation="ad.user.group-membership.change",
        target=target,
        correlation_id="",
        idempotency_key="joiner/alice/vpn-membership",
        changed=True,
        output={"changed": True, "requestedPresent": True},
        approval=approval,
        verification=Verification(check="membership readback", passed=True),
    )
    assert grant not in str(response)
    assert response["changed"] is True
    assert response["verification"][0]["passed"] is True
    assert response["audit"]["metadata"]["approver"] == "change-manager"


def test_mutation_models_reject_invalid_idempotency_before_execution() -> None:
    with pytest.raises(ValidationError, match="idempotency_key"):
        UserEnabledRequest(
            identity="alice",
            enabled=True,
            idempotency_key="bad key!",
            approval_grant="v1.placeholder.placeholder",
        )
    with pytest.raises(ValidationError, match="idempotency_key"):
        GroupMembershipRequest(
            user_identity="alice",
            group_identity="VPN-Users",
            present=True,
            idempotency_key="bad key!",
            approval_grant="v1.placeholder.placeholder",
        )


def test_write_configuration_fails_closed_without_strong_approval_secret() -> None:
    settings = Settings(ad_writes_enabled=True, ad_approval_secret="short")
    with pytest.raises(ValueError, match="32 bytes"):
        settings.validate_write_boundary()
    Settings(
        ad_writes_enabled=True,
        ad_approval_secret="x" * 32,
    ).validate_write_boundary()


def test_credential_bootstrap_configuration_is_separately_fail_closed() -> None:
    with pytest.raises(ValueError, match="AD_WRITES_ENABLED=true"):
        Settings(
            ad_credential_bootstrap_enabled=True,
            ad_approval_secret="x" * 32,
            ad_credential_secret_directory="C:/runtime/secrets",
            ad_credential_receipt_store="C:/runtime/state/receipts.json",
        ).validate_write_boundary()

    with pytest.raises(ValueError, match="AD_CREDENTIAL_SECRET_DIRECTORY"):
        Settings(
            ad_writes_enabled=True,
            ad_approval_secret="x" * 32,
            ad_credential_bootstrap_enabled=True,
            ad_credential_receipt_store="C:/runtime/state/receipts.json",
        ).validate_write_boundary()

    with pytest.raises(ValueError, match="AD_CREDENTIAL_RECEIPT_STORE"):
        Settings(
            ad_writes_enabled=True,
            ad_approval_secret="x" * 32,
            ad_credential_bootstrap_enabled=True,
            ad_credential_secret_directory="C:/runtime/secrets",
        ).validate_write_boundary()

    Settings(
        ad_writes_enabled=True,
        ad_approval_secret="x" * 32,
        ad_credential_bootstrap_enabled=True,
        ad_credential_secret_directory="C:/runtime/secrets",
        ad_credential_receipt_store="C:/runtime/state/receipts.json",
    ).validate_write_boundary()
