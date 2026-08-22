from uuid import uuid4

import pytest
from mcp_common.approval_grants import issue_approval_grant
from mcp_common.operations import ApprovalState, Verification

from ad_mcp.changes import (
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
        current={"enabled": True, "objectGuid": "guid-1"},
        correlation_id=correlation_id,
        idempotency_key="offboard/alice/disable",
    )
    plan = result["plan"]
    assert plan["pre_state"] == {"enabled": True, "objectGuid": "guid-1"}
    assert plan["approval"]["state"] == "required"
    assert plan["risk"] == "high"
    assert plan["steps"][0]["rollback_action"] == "restore enabled=true"
    assert result["alreadySatisfied"] is False
    assert result["audit"]["context"]["correlation_id"] == correlation_id


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


def test_signed_grant_is_bound_to_exact_ad_target_and_idempotency_key() -> None:
    target = user_enabled_target("alice")
    grant = issue_approval_grant(
        SECRET,
        operation="ad.user.enabled.change",
        target=target,
        idempotency_key="joiner/alice/enable",
        approver="change-manager",
        reason="approved onboarding",
    )
    approval = authorize_change(
        grant=grant,
        secret=SECRET,
        operation="ad.user.enabled.change",
        target=target,
        idempotency_key="joiner/alice/enable",
    )
    assert approval.state == ApprovalState.APPROVED
    with pytest.raises(ValueError, match="does not match"):
        authorize_change(
            grant=grant,
            secret=SECRET,
            operation="ad.user.enabled.change",
            target=user_enabled_target("bob"),
            idempotency_key="joiner/alice/enable",
        )


def test_change_response_never_contains_approval_grant() -> None:
    target = group_membership_target("alice", "VPN-Users")
    grant = issue_approval_grant(
        SECRET,
        operation="ad.user.group-membership.change",
        target=target,
        idempotency_key="joiner/alice/vpn-membership",
        approver="change-manager",
        reason="approved onboarding",
    )
    approval = authorize_change(
        grant=grant,
        secret=SECRET,
        operation="ad.user.group-membership.change",
        target=target,
        idempotency_key="joiner/alice/vpn-membership",
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


def test_write_configuration_fails_closed_without_strong_approval_secret() -> None:
    settings = Settings(ad_writes_enabled=True, ad_approval_secret="short")
    with pytest.raises(ValueError, match="32 bytes"):
        settings.validate_write_boundary()
    Settings(
        ad_writes_enabled=True,
        ad_approval_secret="x" * 32,
    ).validate_write_boundary()
