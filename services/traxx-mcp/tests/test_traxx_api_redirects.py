"""SEC-048 regression tests for credential-bearing Traxx API redirects."""

from pathlib import Path
from typing import Any

import httpx
import pytest

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig
from traxx_mcp.tus import TusUnsupported


def make_client(handler: Any) -> tuple[TraxxClient, httpx.MockTransport]:
    config = RuntimeConfig(
        base_url="https://traxx.test",
        token="traxx-token",
        extra_headers={"X-WAF-Key": "proxy-secret"},
    )
    return TraxxClient(config, downloads_dir=Path(".")), httpx.MockTransport(handler)


def install_transport(
    transport: httpx.MockTransport,
    monkeypatch: pytest.MonkeyPatch,
) -> list[bool | None]:
    original = httpx.AsyncClient
    follow_redirects: list[bool | None] = []

    def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        follow_redirects.append(kwargs.get("follow_redirects"))
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)
    return follow_redirects


@pytest.mark.asyncio
async def test_cross_origin_api_redirect_is_not_followed_or_given_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.url.host or "",
                request.headers.get("authorization", ""),
                request.headers.get("x-waf-key", ""),
            )
        )
        if request.url.host != "traxx.test":
            raise AssertionError(f"cross-origin request escaped to {request.url}")
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.test/collect"},
        )

    client, transport = make_client(handler)
    follow_redirects = install_transport(transport, monkeypatch)

    with pytest.raises(TraxxError) as captured:
        await client.request("GET", "/api/v1/users/me", allow_error=True)

    assert captured.value.status_code == 302
    assert captured.value.method == "GET"
    assert captured.value.mutation_ambiguous is False
    assert seen == [("traxx.test", "Bearer traxx-token", "proxy-secret")]
    assert follow_redirects == [False]


@pytest.mark.asyncio
async def test_same_origin_api_redirect_also_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/v1/old":
            return httpx.Response(307, headers={"Location": "/api/v1/new"})
        raise AssertionError(f"redirect was followed to {request.url}")

    client, transport = make_client(handler)
    install_transport(transport, monkeypatch)

    with pytest.raises(TraxxError) as captured:
        await client.request("GET", "/api/v1/old")

    assert captured.value.status_code == 307
    assert paths == ["/api/v1/old"]


@pytest.mark.asyncio
async def test_mutating_api_redirect_is_ambiguous_and_never_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(
            308,
            headers={"Location": "https://attacker.test/replay"},
        )

    client, transport = make_client(handler)
    install_transport(transport, monkeypatch)

    with pytest.raises(TraxxError) as captured:
        await client.request("POST", "/api/v1/playlists", json={"name": "x"})

    assert captured.value.status_code == 308
    assert captured.value.method == "POST"
    assert captured.value.mutation_ambiguous is True
    assert methods == ["POST"]


@pytest.mark.asyncio
async def test_tus_endpoint_discovery_never_follows_cross_origin_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.url.host or "",
                request.method,
                request.headers.get("authorization", ""),
                request.headers.get("x-waf-key", ""),
            )
        )
        if request.url.host != "traxx.test":
            raise AssertionError(f"TUS discovery escaped to {request.url}")
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.test/tus"},
        )

    client, transport = make_client(handler)
    follow_redirects = install_transport(transport, monkeypatch)

    with pytest.raises(TusUnsupported, match="redirect refused"):
        await client._resolve_tus_endpoint()

    assert seen
    assert all(host == "traxx.test" and method == "OPTIONS" for host, method, _, _ in seen)
    assert all(auth == "Bearer traxx-token" and waf == "proxy-secret" for _, _, auth, waf in seen)
    assert follow_redirects == [False]


@pytest.mark.asyncio
async def test_non_redirect_response_still_returns_normally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "traxx.test"
        assert request.headers["Authorization"] == "Bearer traxx-token"
        assert request.headers["X-WAF-Key"] == "proxy-secret"
        return httpx.Response(200, json={"ok": True})

    client, transport = make_client(handler)
    install_transport(transport, monkeypatch)

    assert await client.request("GET", "/api/v1/ping") == {"ok": True}
