from __future__ import annotations

import asyncio

import pytest
from mcp_common.mcp_security import build_mcp_server_security

from example_mcp.config import Settings
from example_mcp.server import create_server


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "mcp_host": "127.0.0.1",
        "mcp_port": 8080,
        "mcp_trust_boundary": "internal",
        "mcp_allowed_hosts": "",
        "mcp_allowed_origins": "",
        "mcp_public_url": "",
        "mcp_issuer_url": "",
        "mcp_auth_token": "",
    }
    values.update(overrides)
    return Settings(**values)


def test_internal_template_enables_dns_rebinding_protection() -> None:
    security = build_mcp_server_security(_settings(), service_hosts=("mcp-example",))

    assert security.auth is None
    assert security.token_verifier is None
    assert security.transport_security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.transport_security.allowed_hosts
    assert "[::1]:*" in security.transport_security.allowed_hosts
    assert "mcp-example:*" in security.transport_security.allowed_hosts
    assert "http://127.0.0.1:*" in security.transport_security.allowed_origins


def test_template_server_fails_closed_without_external_public_url() -> None:
    with pytest.raises(ValueError, match="requires MCP_PUBLIC_URL"):
        create_server(_settings(mcp_trust_boundary="external"))


def test_template_server_fails_closed_without_external_bearer_token() -> None:
    with pytest.raises(ValueError, match="requires MCP_AUTH_TOKEN"):
        create_server(
            _settings(
                mcp_trust_boundary="external",
                mcp_public_url="https://mcp.example.test/mcp",
            )
        )


def test_external_non_loopback_http_is_rejected() -> None:
    with pytest.raises(ValueError, match="must use https"):
        create_server(
            _settings(
                mcp_host="0.0.0.0",
                mcp_trust_boundary="external",
                mcp_public_url="http://mcp.example.test/mcp",
                mcp_auth_token="correct-horse-battery-staple",
            )
        )


def test_external_template_requires_exact_bearer_and_public_host_origin() -> None:
    settings = _settings(
        mcp_host="0.0.0.0",
        mcp_trust_boundary="external",
        mcp_public_url="https://mcp.example.test/mcp",
        mcp_auth_token="correct-horse-battery-staple",
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-example",))

    assert security.auth is not None
    assert security.auth.required_scopes == ["mcp"]
    assert security.token_verifier is not None
    assert "mcp.example.test" in security.transport_security.allowed_hosts
    assert "https://mcp.example.test" in security.transport_security.allowed_origins

    accepted = asyncio.run(
        security.token_verifier.verify_token("correct-horse-battery-staple")
    )
    rejected = asyncio.run(security.token_verifier.verify_token("wrong-token"))
    assert accepted is not None
    assert accepted.resource == "https://mcp.example.test/mcp"
    assert rejected is None
