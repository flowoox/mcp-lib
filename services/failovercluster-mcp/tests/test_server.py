from uuid import uuid4

from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from failovercluster_mcp.server import _response


def test_response_carries_read_only_audit_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=64)
    response = _response(
        "failovercluster.cluster.observe",
        actor="admin:alice",
        reason="cluster diagnosis",
        correlation_id=correlation_id,
        output={"cluster": {"clusterName": "cluster01"}},
        budget=budget,
        target="cluster01",
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["audit"]["risk"] == "read_only"
    assert response["context"]["correlation_id"] == correlation_id
    assert response["output"]["queryBudget"]["requests_used"] == 1
