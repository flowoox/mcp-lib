import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from hyperv_mcp.config import Settings
from hyperv_mcp.transport import HyperVReadOnlyTransport


class FakeRunner:
    def __init__(self, result: dict):
        self.result = result
        self.calls = []

    def run(self, script_id, target, payload, *, timeout_seconds, max_response_bytes):
        self.calls.append((script_id, target, payload, timeout_seconds, max_response_bytes))
        return self.result, 128


def _settings() -> Settings:
    return Settings(
        hyperv_backend_read_only=True,
        hyperv_require_jea=False,
        hyperv_targets_json='{"local":{"computer_name":".","transport":"local"}}',
    )


@pytest.mark.asyncio
async def test_vm_list_is_typed_bounded_and_uses_configured_target() -> None:
    runner = FakeRunner(
        {
            "items": [
                {
                    "id": "vm-guid",
                    "name": "vm01",
                    "state": "Running",
                    "status": "Operating normally",
                    "generation": 2,
                    "version": "10.0",
                    "uptimeSeconds": 120,
                    "cpuUsagePercent": 4,
                    "memoryAssignedBytes": 1024,
                    "memoryDemandBytes": 900,
                    "processorCount": 2,
                    "clustered": False,
                }
            ],
            "nextCursor": None,
        }
    )
    transport = HyperVReadOnlyTransport(_settings(), runner=runner)
    page = await transport.query(
        ReadOnlyQuery(
            operation="hyperv.vm.list",
            parameters={"target_id": "local"},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert page.items[0]["name"] == "vm01"
    assert runner.calls[0][2]["limit"] == 10
    assert runner.calls[0][2]["offset"] == 0


@pytest.mark.asyncio
async def test_transport_rejects_arbitrary_target_and_vm_wildcards() -> None:
    runner = FakeRunner({"items": [], "nextCursor": None})
    transport = HyperVReadOnlyTransport(_settings(), runner=runner)
    with pytest.raises(PermissionError, match="target"):
        await transport.query(
            ReadOnlyQuery(
                operation="hyperv.vm.list",
                parameters={"target_id": "unknown"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    with pytest.raises(ValueError, match="wildcard"):
        await transport.query(
            ReadOnlyQuery(
                operation="hyperv.vm.observe",
                parameters={"target_id": "local", "vm_name": "prod-*"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )


@pytest.mark.asyncio
async def test_events_use_fixed_log_ids_and_bounded_lookback() -> None:
    runner = FakeRunner({"items": [], "nextCursor": None})
    transport = HyperVReadOnlyTransport(_settings(), runner=runner)
    with pytest.raises(ValueError, match="log_id"):
        await transport.query(
            ReadOnlyQuery(
                operation="hyperv.event.list",
                parameters={"target_id": "local", "log_id": "System"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    with pytest.raises(ValueError, match="lookback_minutes"):
        await transport.query(
            ReadOnlyQuery(
                operation="hyperv.event.list",
                parameters={
                    "target_id": "local",
                    "log_id": "vmms",
                    "lookback_minutes": 50_000,
                },
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
