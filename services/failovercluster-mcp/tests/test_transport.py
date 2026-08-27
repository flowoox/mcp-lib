import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from failovercluster_mcp.config import Settings
from failovercluster_mcp.transport import FailoverClusterReadOnlyTransport


class FakeRunner:
    def __init__(self, result: dict):
        self.result = result
        self.calls = []

    def run(self, script_id, target, payload, *, timeout_seconds, max_response_bytes):
        self.calls.append((script_id, target, payload, timeout_seconds, max_response_bytes))
        return self.result, 128


def _settings() -> Settings:
    return Settings(
        failovercluster_backend_read_only=True,
        failovercluster_require_jea=False,
        failovercluster_targets_json='{"local":{"computer_name":".","transport":"local"}}',
    )


@pytest.mark.asyncio
async def test_node_list_is_typed_bounded_and_uses_configured_target() -> None:
    runner = FakeRunner(
        {
            "items": [
                {
                    "name": "node01",
                    "state": "Up",
                    "nodeWeight": 1,
                    "dynamicWeight": 1,
                    "drainStatus": "NotInitiated",
                }
            ],
            "nextCursor": None,
        }
    )
    transport = FailoverClusterReadOnlyTransport(_settings(), runner=runner)
    page = await transport.query(
        ReadOnlyQuery(
            operation="failovercluster.node.list",
            parameters={"target_id": "local"},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert page.items[0]["name"] == "node01"
    assert runner.calls[0][2]["limit"] == 10
    assert runner.calls[0][2]["offset"] == 0


@pytest.mark.asyncio
async def test_transport_rejects_arbitrary_target_and_group_wildcards() -> None:
    runner = FakeRunner({"items": [], "nextCursor": None})
    transport = FailoverClusterReadOnlyTransport(_settings(), runner=runner)
    with pytest.raises(PermissionError, match="target"):
        await transport.query(
            ReadOnlyQuery(
                operation="failovercluster.node.list",
                parameters={"target_id": "unknown"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    with pytest.raises(ValueError, match="wildcard"):
        await transport.query(
            ReadOnlyQuery(
                operation="failovercluster.group.observe",
                parameters={"target_id": "local", "group_name": "prod-*"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )


@pytest.mark.asyncio
async def test_events_have_fixed_log_and_bounded_lookback() -> None:
    runner = FakeRunner({"items": [], "nextCursor": None})
    transport = FailoverClusterReadOnlyTransport(_settings(), runner=runner)
    with pytest.raises(ValueError, match="lookback_minutes"):
        await transport.query(
            ReadOnlyQuery(
                operation="failovercluster.event.list",
                parameters={"target_id": "local", "lookback_minutes": 50_000},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    with pytest.raises(ValueError, match="unsupported parameters"):
        await transport.query(
            ReadOnlyQuery(
                operation="failovercluster.event.list",
                parameters={"target_id": "local", "log_name": "System"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )


@pytest.mark.asyncio
async def test_backend_cannot_return_more_items_than_requested() -> None:
    runner = FakeRunner(
        {
            "items": [
                {"name": "node01", "state": "Up", "nodeWeight": 1, "dynamicWeight": 1, "drainStatus": None},
                {"name": "node02", "state": "Up", "nodeWeight": 1, "dynamicWeight": 1, "drainStatus": None},
            ],
            "nextCursor": None,
        }
    )
    transport = FailoverClusterReadOnlyTransport(_settings(), runner=runner)
    with pytest.raises(ValueError, match="more items"):
        await transport.query(
            ReadOnlyQuery(
                operation="failovercluster.node.list",
                parameters={"target_id": "local"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
