from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from n8n_mcp.config import Settings
from n8n_mcp.contract import capabilities
from n8n_mcp.server import _connector_policy, _reason, _response


def test_policy_is_explicit_read_only_allowlist() -> None:
    policy = _connector_policy(Settings())
    assert policy.require_read_only_backend is True
    assert policy.aggregate_before_fan_out is True
    assert policy.allowed_operations == frozenset(
        {
            "n8n.workflows.list",
            "n8n.executions.list",
            "n8n.executions.get",
        }
    )


def test_capabilities_explicitly_exclude_sensitive_and_write_surfaces() -> None:
    policy = _connector_policy(Settings())
    payload = capabilities(
        policy,
        QueryBudgetLimits(),
        workflow_allowlist_configured=True,
    )
    assert payload["mode"] == "read_only"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["projectIdReliedOnForAuthorization"] is False
    assert payload["safety"]["workflowDefinitionsReturned"] is False
    assert payload["safety"]["executionPayloadDataReturned"] is False
    assert payload["safety"]["credentialValuesReturned"] is False
    assert payload["safety"]["workflowTriggerExposed"] is False


def test_response_carries_audit_correlation_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=64)
    response = _response(
        "n8n.workflows.list",
        actor="admin:alice",
        reason="automation incident diagnosis",
        correlation_id=correlation_id,
        output={"items": []},
        budget=budget,
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["context"]["actor"] == "admin:alice"
    assert response["context"]["correlation_id"] == correlation_id
    assert response["audit"]["risk"] == "read_only"
    assert response["audit"]["metadata"] == {"reason": "automation incident diagnosis"}
    assert response["output"]["queryBudget"]["requests_used"] == 1


def test_reason_and_correlation_fail_closed() -> None:
    with pytest.raises(ValueError, match="reason"):
        _reason(" ")
    with pytest.raises(ValueError, match="UUID"):
        _response(
            "n8n.workflows.list",
            actor="admin:alice",
            reason="diagnosis",
            correlation_id="invalid",
            output={},
            budget=QueryBudget(QueryBudgetLimits()),
        )
