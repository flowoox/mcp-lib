import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from entra_mcp.client import GraphReadOnlyTransport
from entra_mcp.config import Settings

TENANT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
CLIENT = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "entra_tenant_id": TENANT,
        "entra_client_id": CLIENT,
        "entra_client_secret": "test-secret",
        "entra_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


def test_transport_requires_read_only_attestation() -> None:
    with pytest.raises(ValueError, match="BACKEND_READ_ONLY"):
        GraphReadOnlyTransport(_settings(entra_backend_read_only=False))


@pytest.mark.asyncio
async def test_graph_query_uses_fixed_get_projection_and_token_cache() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.url.host == "login.microsoftonline.com":
            assert request.method == "POST"
            body = request.content.decode()
            assert "grant_type=client_credentials" in body
            assert "client_secret=test-secret" in body
            return httpx.Response(
                200,
                json={"access_token": "token-1", "expires_in": 3600},
            )
        assert request.method == "GET"
        assert request.url.path == "/v1.0/users"
        assert request.headers["Authorization"] == "Bearer token-1"
        assert request.url.params["$top"] == "2"
        assert request.url.params["$select"].startswith("id,displayName,userPrincipalName")
        payload = {
            "value": [
                {"id": "u1", "displayName": "Alice", "custom": "drop"},
                {"id": "u2", "displayName": "Bob"},
            ],
            "@odata.nextLink": (
                "https://graph.microsoft.com/v1.0/users?"
                "$select=id%2CdisplayName%2CuserPrincipalName%2CaccountEnabled%2CuserType%2Cmail%2CcreatedDateTime"
                "&$top=2&$skiptoken=opaque123"
            ),
        }
        return httpx.Response(200, content=json.dumps(payload).encode())

    transport = GraphReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        ReadOnlyQuery(operation="entra.user.inventory", page=PageRequest(limit=2)),
        timeout_seconds=2.0,
        max_response_bytes=64_000,
    )
    assert [item["displayName"] for item in page.items] == ["Alice", "Bob"]
    assert "custom" not in page.items[0]
    assert page.truncated is True
    assert page.next_cursor is not None

    await transport.query(
        ReadOnlyQuery(
            operation="entra.user.inventory",
            page=PageRequest(limit=2, cursor=page.next_cursor),
        ),
        timeout_seconds=2.0,
        max_response_bytes=64_000,
    )
    assert sum(1 for method, url in calls if method == "POST" and "oauth2" in url) == 1


@pytest.mark.asyncio
async def test_cursor_cannot_switch_graph_endpoint() -> None:
    transport = GraphReadOnlyTransport(_settings(), transport=httpx.MockTransport(lambda request: httpx.Response(500)))
    with pytest.raises(ValueError, match="fixed endpoint"):
        await transport.query(
            ReadOnlyQuery(
                operation="entra.user.inventory",
                page=PageRequest(
                    limit=10,
                    cursor="https://graph.microsoft.com/v1.0/applications?$skiptoken=oops",
                ),
            ),
            timeout_seconds=2.0,
            max_response_bytes=64_000,
        )
