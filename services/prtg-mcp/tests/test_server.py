from uuid import uuid4

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from prtg_mcp.config import Settings
from prtg_mcp.server import _connector_policy, _reason, _response


def test_policy_is_explicit_read_only_allowlist() -> None:
    policy = _connector_policy(Settings())
    assert policy.require_read_only_backend is True
    assert policy.aggregate_before_fan_out is True
    assert policy.allowed_operations == frozenset(
        {
            "prtg.system.health-status",
            "prtg.system.health-data",
            "prtg.devices.list",
            "prtg.sensors.list",
            "prtg.alarms.list",
            "prtg.channels.list",
            "prtg.messages.list",
            "prtg.historic.sensor",
        }
    )


def test_response_carries_audit_correlation_and_budget() -> None:
    correlation_id = str(uuid4())
    budget = QueryBudget(QueryBudgetLimits())
    budget.reserve_request()
    budget.record_response(items=1, response_bytes=64)
    response = _response(
        "prtg.health-status.observe",
        actor="admin:alice",
        reason="monitoring incident diagnosis",
        correlation_id=correlation_id,
        output={"items": []},
        budget=budget,
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["context"]["actor"] == "admin:alice"
    assert response["context"]["correlation_id"] == correlation_id
    assert response["audit"]["risk"] == "read_only"
    assert response["audit"]["metadata"] == {"reason": "monitoring incident diagnosis"}
    assert response["output"]["queryBudget"]["requests_used"] == 1


def test_reason_and_correlation_fail_closed() -> None:
    with pytest.raises(ValueError, match="reason"):
        _reason(" ")
    with pytest.raises(ValueError, match="UUID"):
        _response(
            "prtg.health-status.observe",
            actor="admin:alice",
            reason="diagnosis",
            correlation_id="invalid",
            output={},
            budget=QueryBudget(QueryBudgetLimits()),
        )
