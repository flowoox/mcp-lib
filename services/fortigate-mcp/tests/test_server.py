from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from fortigate_mcp.server import _observe_response, _reason


def test_observe_response_carries_audit_correlation_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=10)
    response = _observe_response(
        "fortigate.system.observe",
        actor="admin:alice",
        reason="incident diagnosis",
        correlation_id=correlation_id,
        output={"vdom": "root"},
        budget=budget,
        target="fortigate:vdom:root",
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["context"]["actor"] == "admin:alice"
    assert response["context"]["correlation_id"] == correlation_id
    assert response["audit"]["metadata"] == {"reason": "incident diagnosis"}
    assert response["output"]["queryBudget"]["requests_used"] == 1


def test_reason_and_correlation_fail_closed() -> None:
    with pytest.raises(ValueError, match="reason"):
        _reason(" ")
    with pytest.raises(ValueError, match="UUID"):
        _observe_response(
            "fortigate.system.observe",
            actor="admin:alice",
            reason="diagnosis",
            correlation_id="not-a-uuid",
            output={},
            budget=QueryBudget(QueryBudgetLimits()),
            target="fortigate:vdom:root",
        )
