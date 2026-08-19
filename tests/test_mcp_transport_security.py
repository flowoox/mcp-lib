from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware
from mcp_common.mcp_security import build_mcp_server_security
from starlette.requests import Request


def _settings(**overrides):
    values = {
        "mcp_trust_boundary": "internal",
        "mcp_allowed_hosts": "",
        "mcp_allowed_origins": "",
        "mcp_public_url": "",
        "mcp_issuer_url": "",
        "mcp_auth_token": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _request(*, host: str, origin: str | None = None) -> Request:
    headers = [(b"host", host.encode())]
    if origin:
        headers.append((b"origin", origin.encode()))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8082),
        }
    )


@pytest.mark.asyncio
async def test_host_and_origin_allowlist_blocks_rebinding_requests():
    security = build_mcp_server_security(_settings(), service_hosts=("mcp-traxx",))
    middleware = TransportSecurityMiddleware(security.transport_security)

    bad_host = await middleware.validate_request(_request(host="evil.example"))
    assert bad_host is not None
    assert bad_host.status_code == 421

    bad_origin = await middleware.validate_request(
        _request(host="localhost:8082", origin="https://evil.example")
    )
    assert bad_origin is not None
    assert bad_origin.status_code == 403

    local = await middleware.validate_request(
        _request(host="localhost:8082", origin="http://localhost:3000")
    )
    assert local is None

    compose = await middleware.validate_request(_request(host="mcp-traxx:8082"))
    assert compose is None


@pytest.mark.asyncio
async def test_external_boundary_fails_closed_and_requires_bearer_auth():
    with pytest.raises(ValueError, match="MCP_PUBLIC_URL"):
        build_mcp_server_security(
            _settings(mcp_trust_boundary="external"),
            service_hosts=("mcp-traxx",),
        )

    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        build_mcp_server_security(
            _settings(
                mcp_trust_boundary="external",
                mcp_public_url="https://mcp.example.test/mcp",
            ),
            service_hosts=("mcp-traxx",),
        )

    security = build_mcp_server_security(
        _settings(
            mcp_trust_boundary="external",
            mcp_public_url="https://mcp.example.test/mcp",
            mcp_auth_token="test-only-token",
        ),
        service_hosts=("mcp-traxx",),
    )
    assert security.auth is not None
    assert security.token_verifier is not None
    assert await security.token_verifier.verify_token("wrong-token") is None
    accepted = await security.token_verifier.verify_token("test-only-token")
    assert accepted is not None
    assert accepted.scopes == ["mcp"]


def test_external_non_loopback_http_is_rejected():
    with pytest.raises(ValueError, match="must use https"):
        build_mcp_server_security(
            _settings(
                mcp_trust_boundary="external",
                mcp_public_url="http://mcp.example.test/mcp",
                mcp_auth_token="test-only-token",
            ),
            service_hosts=("mcp-traxx",),
        )
