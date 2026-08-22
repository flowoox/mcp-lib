import asyncio
from typing import Any

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetExceeded, QueryBudgetLimits
from mcp_common.read_only_connector import (
    CacheHint,
    PageRequest,
    ReadOnlyConnector,
    ReadOnlyConnectorError,
    ReadOnlyConnectorPolicy,
    ReadOnlyConnectorTimeout,
    ReadOnlyPage,
    ReadOnlyQuery,
    SampleRequest,
)


class FakeTransport:
    def __init__(
        self,
        *,
        read_only: bool = True,
        items: list[Any] | None = None,
        payload_bytes: int = 1_024,
        delay: float = 0.0,
    ) -> None:
        self.read_only = read_only
        self.items = items if items is not None else [{"id": 1}]
        self.payload_bytes = payload_bytes
        self.delay = delay
        self.calls: list[ReadOnlyQuery] = []
        self.active = 0
        self.max_active = 0
        self.response_limits: list[int] = []

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        self.calls.append(query)
        self.response_limits.append(max_response_bytes)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(self.delay)
            return ReadOnlyPage(
                items=self.items,
                payload_bytes=self.payload_bytes,
                next_cursor="next" if self.items else None,
            )
        finally:
            self.active -= 1


def policy(**overrides: Any) -> ReadOnlyConnectorPolicy:
    values: dict[str, Any] = {
        "connector_name": "test.connector",
        "allowed_operations": frozenset({"test.items.list"}),
        "max_page_size": 50,
        "max_sample_size": 5,
        "request_timeout_seconds": 1.0,
        "max_response_bytes": 2_048,
        "max_concurrency": 2,
        "rate_limit_per_second": 10_000,
    }
    values.update(overrides)
    return ReadOnlyConnectorPolicy(**values)


def budget(*, requests: int = 8) -> QueryBudget:
    return QueryBudget(
        QueryBudgetLimits(
            max_requests=requests,
            max_items=100,
            max_response_bytes=20_000,
            max_fan_out=20,
            total_timeout_seconds=5,
        )
    )


def test_connector_requires_explicit_read_only_backend() -> None:
    with pytest.raises(ValueError, match="read-only backend"):
        ReadOnlyConnector(policy(), FakeTransport(read_only=False))


def test_unknown_operation_is_rejected_before_backend_call() -> None:
    transport = FakeTransport()
    connector = ReadOnlyConnector(policy(), transport)

    with pytest.raises(PermissionError, match="allowlist"):
        asyncio.run(
            connector.execute(ReadOnlyQuery(operation="test.items.delete"), budget())
        )

    assert transport.calls == []


def test_query_is_rejected_before_dispatch_when_page_exceeds_remaining_budget() -> None:
    transport = FakeTransport()
    connector = ReadOnlyConnector(policy(), transport)
    query_budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=2,
            max_items=2,
            max_response_bytes=1_024,
            max_fan_out=2,
        )
    )

    with pytest.raises(QueryBudgetExceeded, match="remaining query-budget item capacity"):
        asyncio.run(
            connector.execute(
                ReadOnlyQuery(
                    operation="test.items.list",
                    page=PageRequest(limit=3),
                ),
                query_budget,
            )
        )

    assert transport.calls == []


def test_transport_byte_limit_is_clipped_to_remaining_budget() -> None:
    transport = FakeTransport(payload_bytes=100)
    connector = ReadOnlyConnector(policy(), transport)
    query_budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=2,
            max_items=10,
            max_response_bytes=1_024,
            max_fan_out=2,
        )
    )

    asyncio.run(
        connector.execute(
            ReadOnlyQuery(
                operation="test.items.list",
                page=PageRequest(limit=10),
            ),
            query_budget,
        )
    )

    assert transport.response_limits == [1_024]


def test_paging_sampling_budget_and_cache_hint_are_applied() -> None:
    transport = FakeTransport(items=[{"id": value} for value in range(7)])
    connector = ReadOnlyConnector(
        policy(default_cache_max_age_seconds=30),
        transport,
    )
    query_budget = budget()

    page = asyncio.run(
        connector.execute(
            ReadOnlyQuery(
                operation="test.items.list",
                page=PageRequest(limit=7, cursor="opaque"),
                sample=SampleRequest(size=3, strategy="even"),
            ),
            query_budget,
        )
    )

    assert [item["id"] for item in page.items] == [0, 3, 6]
    assert page.sampled is True
    assert page.truncated is True
    assert page.next_cursor == "next"
    assert page.cache_hint == CacheHint(max_age_seconds=30)
    assert query_budget.snapshot().items_used == 7


def test_unaggregated_fan_out_is_rejected() -> None:
    connector = ReadOnlyConnector(policy(), FakeTransport())

    with pytest.raises(PermissionError, match="aggregate-first"):
        asyncio.run(
            connector.execute(
                ReadOnlyQuery(
                    operation="test.items.list",
                    fan_out=2,
                    aggregated=False,
                ),
                budget(),
            )
        )


def test_backend_cannot_exceed_page_or_byte_bounds() -> None:
    too_many = ReadOnlyConnector(policy(), FakeTransport(items=[{}, {}, {}]))
    with pytest.raises(ReadOnlyConnectorError, match="more items"):
        asyncio.run(
            too_many.execute(
                ReadOnlyQuery(
                    operation="test.items.list",
                    page=PageRequest(limit=2),
                ),
                budget(),
            )
        )

    too_large = ReadOnlyConnector(policy(), FakeTransport(payload_bytes=2_049))
    with pytest.raises(ReadOnlyConnectorError, match="byte limit"):
        asyncio.run(
            too_large.execute(
                ReadOnlyQuery(operation="test.items.list"),
                budget(),
            )
        )


def test_connector_timeout_includes_queueing_and_transport() -> None:
    connector = ReadOnlyConnector(
        policy(request_timeout_seconds=0.1),
        FakeTransport(delay=0.2),
    )

    with pytest.raises(ReadOnlyConnectorTimeout, match="exceeded its timeout"):
        asyncio.run(
            connector.execute(ReadOnlyQuery(operation="test.items.list"), budget())
        )


def test_connector_enforces_concurrency_cap() -> None:
    async def exercise() -> int:
        transport = FakeTransport(delay=0.02)
        connector = ReadOnlyConnector(policy(max_concurrency=2), transport)
        query_budget = budget(requests=6)
        await asyncio.gather(
            *[
                connector.execute(
                    ReadOnlyQuery(operation="test.items.list"),
                    query_budget,
                )
                for _ in range(6)
            ]
        )
        return transport.max_active

    assert asyncio.run(exercise()) == 2
