from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from fileshare_mcp.config import Settings
from fileshare_mcp.models import AclObservation, FileAce, ShareAce, ShareRoot
from fileshare_mcp.server import (
    _content_target,
    _full_path,
    _response,
    _search_query,
    explain_access,
)


def test_path_resolution_cannot_escape_configured_root() -> None:
    root = ShareRoot(alias="data", path=r"D:\Shares\Data")
    assert _full_path(root, r"Team\Report.txt") == r"D:\Shares\Data\Team\Report.txt"
    with pytest.raises(ValueError, match="configured root"):
        _full_path(root, r"..\Secrets")
    with pytest.raises(ValueError, match="configured root"):
        _full_path(root, r"C:\Windows")


def test_path_resolution_rejects_ads_devices_and_ambiguous_segments() -> None:
    root = ShareRoot(alias="data", path=r"D:\Shares\Data")
    with pytest.raises(ValueError, match="invalid segment"):
        _full_path(root, r"Team\report.txt:secret")
    with pytest.raises(ValueError, match="device name"):
        _full_path(root, r"Team\NUL.txt")
    with pytest.raises(ValueError, match="canonicalization-ambiguous"):
        _full_path(root, "Team\\report.txt. ")


def test_content_target_requires_global_and_per_root_opt_in_and_safe_extension() -> None:
    disabled = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares","content_read":true}]',
        fileshare_backend_read_only=True,
    )
    with pytest.raises(ValueError, match="disabled"):
        _content_target(disabled, "data", "report.txt", require_text_extension=True)

    enabled = Settings(
        fileshare_roots_json=(
            '[{"alias":"data","path":"D:\\\\Shares","content_read":true},'
            '{"alias":"archive","path":"D:\\\\Archive"}]'
        ),
        fileshare_backend_read_only=True,
        fileshare_content_read_enabled=True,
        fileshare_safe_text_extensions=".txt,.log",
    )
    root, path = _content_target(enabled, "data", "Team\\report.TXT", require_text_extension=True)
    assert root.alias == "data"
    assert path == r"D:\Shares\Team\report.TXT"
    with pytest.raises(ValueError, match="not enabled for this root"):
        _content_target(enabled, "archive", "report.txt", require_text_extension=True)
    with pytest.raises(ValueError, match="extension"):
        _content_target(enabled, "data", "payload.exe", require_text_extension=True)


def test_search_query_is_literal_bounded_and_rejects_control_characters() -> None:
    settings = Settings(fileshare_max_search_query_characters=8)
    assert _search_query(settings, " error ") == "error"
    with pytest.raises(ValueError, match="character limit"):
        _search_query(settings, "123456789")
    with pytest.raises(ValueError, match="control"):
        _search_query(settings, "a\nb")


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
