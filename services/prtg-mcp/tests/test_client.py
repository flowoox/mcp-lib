from __future__ import annotations

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from prtg_mcp.client import PrtgClientError, PrtgReadOnlyTransport
from prtg_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "prtg_base_url": "https://prtg.example.test",
        "prtg_api_key": "super-secret-api-key",
        "prtg_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_device_query_uses_bearer_header_and_fixed_projection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/table.json"
        assert request.headers["Authorization"] == "Bearer super-secret-api-key"
        assert "apitoken" not in request.url.params
        assert request.url.params["content"] == "devices"
        assert request.url.params["count"] == "2"
        assert request.url.params["start"] == "0"
        assert "host" not in request.url.params["columns"]
        return httpx.Response(
            200,
            json={
                "prtg-version": "26.2.121.1606",
                "treesize": 3,
                "devices": [
                    {
                        "objid": 1001,
                        "probe": "Local Probe",
                        "group": "Servers",
                        "device": "hv01",
                        "status": "Up",
                        "status_raw": 3,
                        "message": "OK",
                        "priority": 3,
                        "dependency": "Parent",
                        "active": True,
                        "parentid": 1000,
                        "upsens": 10,
                        "downsens": 0,
                        "totalsens": 10,
                    },
                    {
                        "objid": 1002,
                        "probe": "Local Probe",
                        "group": "Servers",
                        "device": "hv02",
                        "status": "Warning",
                        "status_raw": "4",
                        "message_raw": "CPU warning",
                        "priority_raw": 4,
                        "dependency": "Parent",
                        "active_raw": 1,
                        "parentid_raw": 1000,
                    },
                ],
            },
        )

    client = PrtgReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(operation="prtg.devices.list", page=PageRequest(limit=2)),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )

    assert page.next_cursor == "2"
    assert page.truncated is True
    assert page.items[0]["status_id"] == 3
    assert page.items[0]["sensor_counts"] == {"upsens": 10, "downsens": 0, "totalsens": 10}
    assert page.items[1]["message"] == "CPU warning"


@pytest.mark.asyncio
async def test_alarm_query_uses_only_documented_fixed_problem_states() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.extend(request.url.params.get_list("filter_status"))
        assert request.url.params["sortby"] == "priority"
        return httpx.Response(200, json={"treesize": 0, "sensors": []})

    client = PrtgReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    await client.query(
        ReadOnlyQuery(operation="prtg.alarms.list", page=PageRequest(limit=10)),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert seen == ["4", "5", "10", "13", "14"]


@pytest.mark.asyncio
async def test_health_status_treats_documented_503_as_observation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/healthstatus.json"
        return httpx.Response(503, content=b"")

    client = PrtgReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(operation="prtg.system.health-status", page=PageRequest(limit=1)),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items == [{"healthy": False, "status_code": 503}]


@pytest.mark.asyncio
async def test_messages_are_time_bounded_and_object_scoped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["filter_drel"] == "7days"
        assert request.url.params["id"] == "1234"
        return httpx.Response(
            200,
            json={
                "treesize": 1,
                "messages": [
                    {
                        "objid": 1234,
                        "datetime": "8/25/2026 09:59:00",
                        "parent": "hv01",
                        "type": "System",
                        "name": "Ping",
                        "status": "Down",
                        "message": "timeout",
                        "priority": 4,
                    }
                ],
            },
        )

    client = PrtgReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(
            operation="prtg.messages.list",
            parameters={"window": "7days", "object_id": 1234},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0]["message"] == "timeout"


@pytest.mark.asyncio
async def test_historic_query_is_exact_sensor_bounded_and_uses_no_token_query() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/historicdata.json"
        assert request.url.params["id"] == "2001"
        assert request.url.params["avg"] == "300"
        assert request.url.params["usecaption"] == "1"
        assert "apitoken" not in request.url.params
        return httpx.Response(
            200,
            json={
                "histdata": [
                    {
                        "datetime": "8/25/2026 09:00:00",
                        "Ping Time": "1.2 ms",
                        "Ping Time_raw": 1.2,
                        "Coverage": "100 %",
                        "Coverage_raw": 100.0,
                    },
                    {
                        "datetime": "8/25/2026 09:05:00",
                        "Ping Time": "1.3 ms",
                        "Ping Time_raw": 1.3,
                    },
                ]
            },
        )

    client = PrtgReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
        historic_interval_seconds=0,
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="prtg.historic.sensor",
            parameters={
                "sensor_id": 2001,
                "start": "2026-08-25-09-00-00",
                "end": "2026-08-25-10-00-00",
                "average_seconds": 300,
            },
            page=PageRequest(limit=2),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0]["values"]["Ping Time"] == 1.2
    assert page.items[0]["values"]["Coverage"] == 100.0


@pytest.mark.asyncio
async def test_historic_window_is_rejected_before_backend_dispatch() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("over-broad historic query must not reach PRTG")

    client = PrtgReadOnlyTransport(
        _settings(prtg_historic_max_window_hours=24),
        transport=httpx.MockTransport(handler),
        historic_interval_seconds=0,
    )
    with pytest.raises(ValueError, match="load-safety"):
        await client.query(
            ReadOnlyQuery(
                operation="prtg.historic.sensor",
                parameters={
                    "sensor_id": 2001,
                    "start": "2026-08-20-00-00-00",
                    "end": "2026-08-25-00-00-00",
                    "average_seconds": 3600,
                },
                page=PageRequest(limit=10),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )


@pytest.mark.asyncio
async def test_arbitrary_parameters_redirects_and_oversized_responses_fail_closed() -> None:
    client = PrtgReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "/login"})),
    )
    with pytest.raises(ValueError, match="unsupported parameters"):
        await client.query(
            ReadOnlyQuery(
                operation="prtg.devices.list",
                parameters={"filter_name": "secret"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )

    with pytest.raises(PrtgClientError, match="redirects"):
        await client.query(
            ReadOnlyQuery(operation="prtg.devices.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )

    oversized = PrtgReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"{" + b"x" * 2048 + b"}")
        ),
    )
    with pytest.raises(PrtgClientError, match="byte limit"):
        await oversized.query(
            ReadOnlyQuery(operation="prtg.devices.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=1024,
        )
