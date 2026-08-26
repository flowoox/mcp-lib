from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from fileshare_mcp.models import AclObservation, FileAce, ShareAce, ShareRoot
from fileshare_mcp.server import _full_path, _response, explain_access


def test_path_resolution_cannot_escape_configured_root() -> None:
    root = ShareRoot(alias="data", path=r"D:\Shares\Data")
    assert _full_path(root, r"Team\Report.txt") == r"D:\Shares\Data\Team\Report.txt"
    with pytest.raises(ValueError, match="configured root"):
        _full_path(root, r"..\Secrets")
    with pytest.raises(ValueError, match="configured root"):
        _full_path(root, r"C:\Windows")


def test_access_explanation_is_conservative_and_never_authoritative() -> None:
    acl = AclObservation(
        full_path=r"D:\Shares\Data",
        owner="CONTOSO\\Administrators",
        inheritance_protected=False,
        ntfs=[
            FileAce(
                identity="CONTOSO\\Alice",
                sid="S-1-5-21-100",
                rights="ReadAndExecute",
                access_type="Allow",
                inherited=False,
            )
        ],
        share=[
            ShareAce(
                account_name="CONTOSO\\Blocked",
                sid="S-1-5-21-200",
                access_type="Deny",
                access_right="Full",
            )
        ],
    )
    result = explain_access(acl, "S-1-5-21-100", ["S-1-5-21-200"])
    assert result.conclusion == "matching_deny_present"
    assert result.authoritative is False
    assert len(result.matching_ntfs_aces) == 1
    assert len(result.matching_share_aces) == 1


def test_response_carries_read_only_audit_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=32)
    response = _response(
        "fileshare.path.observe",
        actor="admin:alice",
        reason="permissions diagnosis",
        correlation_id=correlation_id,
        output={"path": {}},
        budget=budget,
        target="data:Team",
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["audit"]["risk"] == "read_only"
    assert response["context"]["correlation_id"] == correlation_id
