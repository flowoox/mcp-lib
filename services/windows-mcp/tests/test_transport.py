from __future__ import annotations

import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from windows_mcp.config import Settings
from windows_mcp.scripts import ScriptId
from windows_mcp.transport import WindowsReadOnlyTransport


class FakeRunner:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or {"items": [], "nextCursor": None}

    def run(self, script_id, target, payload, *, timeout_seconds, max_response_bytes):
        self.calls.append((script_id, target, payload, timeout_seconds, max_response_bytes))
        return self.result, 64


def settings(**kwargs) -> Settings:
    return Settings(windows_backend_read_only=True, **kwargs)


def test_transport_requires_explicit_read_only_backend_attestation() -> None:
    with pytest.raises(ValueError, match="READ_ONLY"):
        WindowsReadOnlyTransport(Settings(), runner=FakeRunner())


@pytest.mark.asyncio
async def test_service_query_resolves_logical_target_and_bounded_cursor() -> None:
    runner = FakeRunner(
        {
            "items": [
                {
                    "name": "Spooler",
                    "displayName": "Print Spooler",
                    "status": "Running",
                    "startType": "Automatic",
                }
            ],
            "nextCursor": "11",
        }
    )
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    page = await transport.query(
        ReadOnlyQuery(
            operation="windows.service.inventory",
            parameters={"target_id": "local", "state": "running"},
            page=PageRequest(limit=10, cursor="1"),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert page.items[0]["name"] == "Spooler"
    assert page.next_cursor == "11"
    assert runner.calls[0][0] == ScriptId.SERVICES
    assert runner.calls[0][2] == {"limit": 10, "offset": 1, "state": "running"}


@pytest.mark.asyncio
async def test_unknown_target_and_event_log_fail_closed_before_runner() -> None:
    runner = FakeRunner()
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    with pytest.raises(PermissionError, match="target"):
        await transport.query(
            ReadOnlyQuery(
                operation="windows.host.inventory",
                parameters={"target_id": "missing"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    with pytest.raises(PermissionError, match="event log"):
        await transport.query(
            ReadOnlyQuery(
                operation="windows.event.inventory",
                parameters={"target_id": "local", "log_name": "Security"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    assert runner.calls == []


@pytest.mark.asyncio
async def test_backend_projection_rejects_unexpected_raw_fields() -> None:
    runner = FakeRunner(
        {
            "items": [
                {
                    "name": "Spooler",
                    "displayName": "Print Spooler",
                    "status": "Running",
                    "startType": "Automatic",
                    "binaryPath": "secret/raw/backend/field",
                }
            ],
            "nextCursor": None,
        }
    )
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    with pytest.raises(Exception, match="binaryPath"):
        await transport.query(
            ReadOnlyQuery(
                operation="windows.service.inventory",
                parameters={"target_id": "local", "state": "all"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )


@pytest.mark.asyncio
async def test_event_query_is_time_bounded_and_messages_are_opt_in() -> None:
    runner = FakeRunner()
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    await transport.query(
        ReadOnlyQuery(
            operation="windows.event.inventory",
            parameters={
                "target_id": "local",
                "log_name": "System",
                "lookback_minutes": 120,
                "level": "warning",
                "include_message": False,
            },
            page=PageRequest(limit=25),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert runner.calls[0][2]["lookbackMinutes"] == 120
    assert runner.calls[0][2]["includeMessage"] is False
    assert runner.calls[0][2]["limit"] == 25


@pytest.mark.asyncio
async def test_process_query_is_fixed_projected_and_bounded() -> None:
    runner = FakeRunner(
        {
            "items": [
                {
                    "processName": "python",
                    "processId": 4242,
                    "cpuSeconds": 3.5,
                    "workingSetBytes": 1048576,
                }
            ],
            "nextCursor": None,
        }
    )
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    page = await transport.query(
        ReadOnlyQuery(
            operation="windows.process.inventory",
            parameters={"target_id": "local", "sort_by": "cpu"},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert page.items[0] == {
        "processName": "python",
        "processId": 4242,
        "cpuSeconds": 3.5,
        "workingSetBytes": 1048576,
    }
    assert runner.calls[0][0] == ScriptId.PROCESSES
    assert runner.calls[0][2]["sortBy"] == "cpu"


@pytest.mark.asyncio
async def test_process_query_rejects_unapproved_sort_expression() -> None:
    runner = FakeRunner()
    transport = WindowsReadOnlyTransport(settings(), runner=runner)
    with pytest.raises(ValueError, match="sort_by"):
        await transport.query(
            ReadOnlyQuery(
                operation="windows.process.inventory",
                parameters={"target_id": "local", "sort_by": "CommandLine"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=5,
            max_response_bytes=4096,
        )
    assert runner.calls == []
