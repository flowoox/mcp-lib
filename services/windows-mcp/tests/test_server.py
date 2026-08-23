from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from windows_mcp.server import _reason, _response


def test_response_carries_logical_target_audit_correlation_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=64)
    response = _response(
        "windows.host.observe",
        target_id="server01",
        actor="admin:alice",
        reason="server incident diagnosis",
        correlation_id=correlation_id,
        output={"items": []},
        budget=budget,
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["context"]["actor"] == "admin:alice"
    assert response["audit"]["target"] == "windows:server01"
    assert response["audit"]["metadata"] == {"reason": "server incident diagnosis"}
    assert response["output"]["queryBudget"]["requests_used"] == 1


def test_reason_and_correlation_fail_closed() -> None:
    with pytest.raises(ValueError, match="reason"):
        _reason(" ")
    with pytest.raises(ValueError, match="UUID"):
        _response(
            "windows.host.observe",
            target_id="local",
            actor="admin:alice",
            reason="diagnosis",
            correlation_id="invalid",
            output={},
            budget=QueryBudget(QueryBudgetLimits()),
        )
