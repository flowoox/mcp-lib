import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetExceeded, QueryBudgetLimits


class Clock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value


def test_budget_accounts_for_pagination_fan_out_items_and_bytes() -> None:
    clock = Clock()
    budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=2,
            max_items=4,
            max_response_bytes=2_048,
            max_fan_out=3,
            total_timeout_seconds=5,
        ),
        clock=clock,
    )

    budget.reserve_request(fan_out=2)
    budget.record_response(items=3, response_bytes=1_024)
    snapshot = budget.snapshot()

    assert snapshot.requests_used == 1
    assert snapshot.requests_remaining == 1
    assert snapshot.items_used == 3
    assert snapshot.response_bytes_remaining == 1_024
    assert snapshot.fan_out_remaining == 1


@pytest.mark.parametrize(
    ("action", "message"),
    [
        (lambda budget: budget.reserve_request(requests=2), "request limit"),
        (lambda budget: budget.reserve_request(fan_out=3), "fan-out limit"),
        (lambda budget: budget.record_response(items=3, response_bytes=0), "item limit"),
        (
            lambda budget: budget.record_response(items=0, response_bytes=2_049),
            "response-byte limit",
        ),
    ],
)
def test_budget_fails_closed_without_partially_charging(action, message: str) -> None:
    budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=1,
            max_items=2,
            max_response_bytes=2_048,
            max_fan_out=2,
        )
    )

    with pytest.raises(QueryBudgetExceeded, match=message):
        action(budget)

    snapshot = budget.snapshot()
    assert snapshot.requests_used == 0
    assert snapshot.items_used == 0
    assert snapshot.response_bytes_used == 0
    assert snapshot.fan_out_used == 0


def test_budget_uses_one_monotonic_total_deadline() -> None:
    clock = Clock()
    budget = QueryBudget(
        QueryBudgetLimits(total_timeout_seconds=2.0),
        clock=clock,
    )
    clock.value += 1.25

    assert budget.remaining_timeout(10.0) == pytest.approx(0.75)

    clock.value += 0.75
    with pytest.raises(QueryBudgetExceeded, match="timeout"):
        budget.reserve_request()
