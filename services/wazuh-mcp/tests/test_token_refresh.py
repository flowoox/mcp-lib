from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from wazuh_mcp.config import Settings
from wazuh_mcp.token_refresh import (
    ExpiringWazuhServerReadOnlyTransport,
    _jwt_expiration_epoch,
)


def _settings() -> Settings:
    return Settings(
        wazuh_server_api_base_url="https://manager.example:55000",
        wazuh_server_username="svc-mcp",
        wazuh_server_password="server-secret",
        wazuh_server_backend_read_only=True,
        wazuh_server_backend_role="readonly",
    )


def _token(expiration: float | None) -> str:
    payload: dict[str, object] = {"sub": "svc-mcp"}
    if expiration is not None:
        payload["exp"] = expiration
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"header.{encoded}.signature-1234567890"


def test_jwt_expiration_epoch_is_parsed_only_when_well_formed() -> None:
    expected = time.time() + 600
    assert _jwt_expiration_epoch(_token(expected)) == pytest.approx(expected)
    assert _jwt_expiration_epoch("not-a-jwt") is None
    assert _jwt_expiration_epoch(_token(None)) is None


@pytest.mark.asyncio
async def test_future_expiration_reuses_cached_token() -> None:
    calls = 0
    token = _token(time.time() + 600)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        assert request.url.path == "/security/user/authenticate"
        calls += 1
        return httpx.Response(200, text=token)

    transport = ExpiringWazuhServerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    first = await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)
    second = await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)

    assert first == second == token
    assert calls == 1


@pytest.mark.asyncio
async def test_near_expiry_token_is_not_cached() -> None:
    calls = 0
    token = _token(time.time() + 5)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text=token)

    transport = ExpiringWazuhServerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)
    await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)

    assert calls == 2


@pytest.mark.asyncio
async def test_missing_exp_disables_cache_instead_of_guessing_lifetime() -> None:
    calls = 0
    token = _token(None)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text=token)

    transport = ExpiringWazuhServerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)
    await transport._authenticate(timeout_seconds=5, max_response_bytes=16_384)

    assert calls == 2
