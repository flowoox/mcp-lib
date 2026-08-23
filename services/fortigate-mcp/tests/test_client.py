import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from fortigate_mcp.client import FortiGateApiTransport
from fortigate_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "fortigate_base_url": "https://fw.example.test",
        "fortigate_api_token": "test-token",
        "fortigate_backend_read_only": True,
        "fortigate_allowed_vdoms": "root;dmz",
        "fortigate_default_vdom": "root",
    }
    values.update(overrides)
    return Settings(**values)


def test_transport_requires_read_only_backend_attestation() -> None:
    with pytest.raises(ValueError, match="BACKEND_READ_ONLY"):
        FortiGateApiTransport(_settings(fortigate_backend_read_only=False))


@pytest.mark.asyncio
async def test_policy_query_uses_fixed_get_projection_and_bounded_paging() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v2/cmdb/firewall/policy"
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.url.params["vdom"] == "dmz"
        assert request.url.params["count"] == "2"
        assert request.url.params["start"] == "0"
        assert "format" in request.url.params
        payload = {
            "status": "success",
            "vdom": "dmz",
            "matched_count": 3,
            "results": [
                {"policyid": 1, "name": "one", "action": "accept", "password": "drop"},
                {"policyid": 2, "name": "two", "action": "deny"},
            ],
        }
        return httpx.Response(200, content=json.dumps(payload).encode(), headers={"content-type": "application/json"})

    transport = FortiGateApiTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        ReadOnlyQuery(
            operation="fortigate.policy.inventory",
            parameters={"vdom": "dmz"},
            page=PageRequest(limit=2),
        ),
        timeout_seconds=2.0,
        max_response_bytes=64_000,
    )
    assert [item["name"] for item in page.items] == ["one", "two"]
    assert "password" not in page.items[0]
    assert page.truncated is True
    assert page.next_cursor == "2"


@pytest.mark.asyncio
async def test_transport_rejects_disallowed_vdom_before_request() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    transport = FortiGateApiTransport(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(PermissionError, match="outside"):
        await transport.query(
            ReadOnlyQuery(
                operation="fortigate.interface.inventory",
                parameters={"vdom": "prod"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=2.0,
            max_response_bytes=64_000,
        )
    assert called is False
