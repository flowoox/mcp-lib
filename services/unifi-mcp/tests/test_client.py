from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from unifi_mcp.client import UniFiClientError, UniFiReadOnlyTransport
from unifi_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "unifi_api_base_url": "https://console.example/proxy/network/integration",
        "unifi_api_key": "secret",
        "unifi_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


def _query(
    operation: str,
    *,
    parameters: dict[str, object] | None = None,
    limit: int = 25,
    cursor: str | None = None,
) -> ReadOnlyQuery:
    return ReadOnlyQuery(
        operation=operation,
        parameters=parameters or {},
        page=PageRequest(limit=limit, cursor=cursor),
        aggregated=True,
    )


def test_transport_fails_closed_without_read_only_attestation() -> None:
    with pytest.raises(ValueError, match="UNIFI_BACKEND_READ_ONLY"):
        UniFiReadOnlyTransport(
            _settings(unifi_backend_read_only=False),
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        )


@pytest.mark.asyncio
async def test_sites_pagination_and_header_are_bounded() -> None:
    site_a, site_b = str(uuid4()), str(uuid4())
    seen_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("X-API-Key", ""))
        assert request.url.path.endswith("/v1/sites")
        assert request.url.params["limit"] == "1"
        if request.url.params["offset"] == "0":
            payload = {
                "offset": 0,
                "limit": 1,
                "count": 1,
                "totalCount": 2,
                "data": [{"id": site_a, "internalReference": "default", "name": "Default"}],
            }
        else:
            payload = {
                "offset": 1,
                "limit": 1,
                "count": 1,
                "totalCount": 2,
                "data": [{"id": site_b, "internalReference": "lab", "name": "Lab"}],
            }
        return httpx.Response(200, json=payload)

    transport = UniFiReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    first = await transport.query(
        _query("unifi.sites.list", limit=1), timeout_seconds=5, max_response_bytes=100_000
    )
    assert first.items == [{"site_id": site_a, "name": "Default"}]
    assert first.next_cursor == "offset:1"
    second = await transport.query(
        _query("unifi.sites.list", limit=1, cursor=first.next_cursor),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    assert second.items[0]["site_id"] == site_b
    assert second.next_cursor is None
    assert seen_headers == ["secret", "secret"]


@pytest.mark.asyncio
async def test_device_projection_omits_mac_ip_and_configuration_id() -> None:
    site_id, device_id = str(uuid4()), str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            json={
                "id": device_id,
                "macAddress": "00:11:22:33:44:55",
                "ipAddress": "192.0.2.50",
                "name": "Switch",
                "model": "USW",
                "state": "ONLINE",
                "supported": True,
                "firmwareVersion": "1.2.3",
                "firmwareUpdatable": False,
                "configurationId": "sensitive-config-id",
                "adoptedAt": "2026-01-01T00:00:00Z",
                "provisionedAt": "2026-01-01T00:00:01Z",
                "uplink": {"deviceId": str(uuid4())},
                "features": {"switching": {}},
                "interfaces": {"ports": [{"idx": 1}], "radios": []},
            },
        )

    transport = UniFiReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        _query(
            "unifi.devices.get",
            parameters={"site_id": site_id, "device_id": device_id},
            limit=1,
        ),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    rendered = json.dumps(page.items)
    assert "00:11:22:33:44:55" not in rendered
    assert "192.0.2.50" not in rendered
    assert "sensitive-config-id" not in rendered
    assert page.items[0]["port_count"] == 1
    assert page.items[0]["has_uplink"] is True


@pytest.mark.asyncio
async def test_client_projection_omits_name_ip_and_mac() -> None:
    site_id, client_id = str(uuid4()), str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": client_id,
                "type": "WIRELESS",
                "name": "Alice Phone",
                "ipAddress": "192.0.2.60",
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "connectedAt": "2026-08-31T07:00:00Z",
                "access": {"type": "GUEST", "authorized": True},
            },
        )

    transport = UniFiReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        _query(
            "unifi.clients.get",
            parameters={"site_id": site_id, "client_id": client_id},
            limit=1,
        ),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    rendered = json.dumps(page.items)
    assert "Alice Phone" not in rendered
    assert "192.0.2.60" not in rendered
    assert "aa:bb:cc:dd:ee:ff" not in rendered
    assert page.items[0]["access_type"] == "GUEST"
    assert page.items[0]["access_authorized"] is True


@pytest.mark.asyncio
async def test_filter_and_unknown_operations_are_rejected_before_dispatch() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    transport = UniFiReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="unsupported parameters"):
        await transport.query(
            _query("unifi.sites.list", parameters={"filter": "name.like('*')"}),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )
    with pytest.raises(PermissionError):
        await transport.query(
            _query("unifi.devices.action"), timeout_seconds=5, max_response_bytes=100_000
        )
    assert called is False


@pytest.mark.asyncio
async def test_redirect_and_oversized_responses_are_rejected() -> None:
    redirect_transport = UniFiReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"Location": "https://evil.example/"})
        ),
    )
    with pytest.raises(UniFiClientError, match="redirect"):
        await redirect_transport.query(
            _query("unifi.application.info", limit=1),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )

    large = json.dumps({"applicationVersion": "x" * 2000}).encode()
    oversized_transport = UniFiReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=large)),
    )
    with pytest.raises(UniFiClientError, match="byte limit"):
        await oversized_transport.query(
            _query("unifi.application.info", limit=1),
            timeout_seconds=5,
            max_response_bytes=128,
        )


@pytest.mark.asyncio
async def test_statistics_projection_keeps_health_metrics_only() -> None:
    site_id, device_id = str(uuid4()), str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "uptimeSec": 123,
                "lastHeartbeatAt": "2026-08-31T07:00:00Z",
                "cpuUtilizationPct": 12.5,
                "memoryUtilizationPct": 42.0,
                "uplink": {"txRateBps": 1000, "rxRateBps": 2000},
                "interfaces": {"radios": [{"frequencyGHz": "5", "txRetriesPct": 1.25}]},
            },
        )

    transport = UniFiReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        _query(
            "unifi.devices.statistics.latest",
            parameters={"site_id": site_id, "device_id": device_id},
            limit=1,
        ),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    item = page.items[0]
    assert item["uptime_seconds"] == 123
    assert item["cpu_utilization_pct"] == 12.5
    assert item["uplink_rx_rate_bps"] == 2000
    assert item["radios"][0]["frequency_ghz"] == "5"
