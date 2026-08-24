from __future__ import annotations

from typing import Any

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits
from mcp_common.read_only_connector import (
    CacheHint,
    ReadOnlyConnector,
    ReadOnlyConnectorPolicy,
    ReadOnlyPage,
    ReadOnlyQuery,
)

from docker_mcp.diagnostics import collect_diagnostic_detail, select_diagnostic_candidates


class FakeDockerTransport:
    read_only = True

    def __init__(self) -> None:
        self.queries: list[ReadOnlyQuery] = []

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        del timeout_seconds, max_response_bytes
        self.queries.append(query)
        if query.operation == "docker.containers.list":
            return ReadOnlyPage(
                items=[
                    {
                        "id": "healthy",
                        "names": ["/healthy"],
                        "state": "running",
                        "status": "Up 2 hours (healthy)",
                    },
                    {
                        "id": "restart-b",
                        "names": ["/restart-b"],
                        "state": "restarting",
                        "status": "Restarting (1) 5 seconds ago",
                    },
                    {
                        "id": "dead-a",
                        "names": ["/dead-a"],
                        "state": "dead",
                        "status": "Dead",
                    },
                    {
                        "id": "bad-health",
                        "names": ["/bad-health"],
                        "state": "running",
                        "status": "Up 10 minutes (unhealthy)",
                    },
                    {
                        "id": "clean-stop",
                        "names": ["/clean-stop"],
                        "state": "exited",
                        "status": "Exited (0) 30 minutes ago",
                    },
                ],
                payload_bytes=500,
                cache_hint=CacheHint(max_age_seconds=5),
            )
        if query.operation == "docker.containers.stats":
            container_id = str(query.parameters["container_id"])
            return ReadOnlyPage(
                items=[{"containerId": container_id, "cpuPercent": 1.5}],
                payload_bytes=100,
                cache_hint=CacheHint(max_age_seconds=2, scope="request"),
            )
        raise AssertionError(f"unexpected operation {query.operation}")


def _connector(transport: FakeDockerTransport) -> ReadOnlyConnector:
    return ReadOnlyConnector(
        ReadOnlyConnectorPolicy(
            connector_name="docker.test.readonly",
            allowed_operations=frozenset(
                {"docker.containers.list", "docker.containers.stats"}
            ),
            max_page_size=100,
            max_sample_size=50,
            request_timeout_seconds=1,
            max_response_bytes=16_384,
            max_concurrency=1,
            rate_limit_per_second=10_000,
            aggregate_before_fan_out=True,
        ),
        transport,
    )


def test_candidate_selection_is_deterministic_and_anomaly_only() -> None:
    selected = select_diagnostic_candidates(
        [
            {"id": "z", "names": ["/z"], "state": "running", "status": "Up (unhealthy)"},
            {"id": "a", "names": ["/a"], "state": "dead", "status": "Dead"},
            {"id": "b", "names": ["/b"], "state": "restarting", "status": "Restarting"},
            {"id": "c", "names": ["/c"], "state": "exited", "status": "Exited (2)"},
            {"id": "d", "names": ["/d"], "state": "exited", "status": "Exited (0)"},
            {"id": "e", "names": ["/e"], "state": "running", "status": "Up (healthy)"},
        ],
        limit=10,
    )

    assert [item["containerId"] for item in selected] == ["a", "b", "z", "c"]
    assert selected[0]["reasons"] == ["state:dead"]
    assert selected[-1]["reasons"] == ["exit:nonzero:2"]


@pytest.mark.asyncio
async def test_detail_fan_out_only_targets_aggregate_selected_candidates() -> None:
    transport = FakeDockerTransport()
    budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=4,
            max_items=100,
            max_response_bytes=16_384,
            max_fan_out=4,
            total_timeout_seconds=5,
        )
    )

    output = await collect_diagnostic_detail(
        _connector(transport),
        budget,
        include_stopped=True,
        inventory_limit=50,
        detail_limit=2,
        operator_max_candidates=3,
    )

    assert output["selection"] == {
        "strategy": "aggregate-first-deterministic-anomaly",
        "inventoryReturned": 5,
        "inventoryTruncated": False,
        "selectedCount": 2,
        "detailLimit": 2,
        "operatorMaxCandidates": 3,
    }
    assert [item["candidate"]["containerId"] for item in output["details"]] == [
        "dead-a",
        "restart-b",
    ]
    assert output["automaticLogsFetched"] is False
    assert output["automaticEventsFetched"] is False
    assert [query.operation for query in transport.queries] == [
        "docker.containers.list",
        "docker.containers.stats",
        "docker.containers.stats",
    ]
    assert [
        query.parameters["container_id"]
        for query in transport.queries
        if query.operation == "docker.containers.stats"
    ] == ["dead-a", "restart-b"]
    assert budget.snapshot().requests_used == 3
    assert budget.snapshot().fan_out_used == 3


@pytest.mark.asyncio
async def test_detail_budget_preflight_rejects_before_backend_work() -> None:
    transport = FakeDockerTransport()
    budget = QueryBudget(
        QueryBudgetLimits(
            max_requests=2,
            max_items=100,
            max_response_bytes=16_384,
            max_fan_out=2,
            total_timeout_seconds=5,
        )
    )

    with pytest.raises(ValueError, match="request limit"):
        await collect_diagnostic_detail(
            _connector(transport),
            budget,
            include_stopped=False,
            inventory_limit=50,
            detail_limit=2,
            operator_max_candidates=3,
        )

    assert transport.queries == []


def test_detail_limit_cannot_exceed_operator_cap() -> None:
    transport = FakeDockerTransport()
    budget = QueryBudget(QueryBudgetLimits())

    with pytest.raises(ValueError, match="DOCKER_DIAGNOSTIC_DETAIL_MAX_CANDIDATES"):
        import asyncio

        asyncio.run(
            collect_diagnostic_detail(
                _connector(transport),
                budget,
                include_stopped=False,
                inventory_limit=50,
                detail_limit=4,
                operator_max_candidates=3,
            )
        )

    assert transport.queries == []
