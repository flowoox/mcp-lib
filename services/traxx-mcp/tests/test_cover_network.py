from __future__ import annotations

from typing import Any

import pytest

from traxx_mcp.client import TraxxError
from traxx_mcp.config import RuntimeConfig
from traxx_mcp.cover_network import (
    CoverFetchError,
    CoverPolicyError,
    CoverResponse,
    fetch_public_cover_sync,
    parse_cover_url,
    validate_public_addresses,
)
from traxx_mcp.secure_client import SecureTraxxClient


def test_private_ipv4_is_blocked_before_request() -> None:
    requests: list[str] = []

    def resolver(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    def request_once(*args: Any, **kwargs: Any):
        requests.append("sent")
        raise AssertionError("request must not be emitted")

    with pytest.raises(CoverPolicyError, match="non-public"):
        fetch_public_cover_sync(
            "http://127.0.0.1/cover.jpg",
            resolver=resolver,
            request_once=request_once,
        )
    assert requests == []


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_private_link_local_metadata_and_mapped_addresses_are_blocked(address: str) -> None:
    with pytest.raises(CoverPolicyError, match="non-public"):
        validate_public_addresses([address])


def test_mixed_public_private_dns_answer_fails_closed() -> None:
    with pytest.raises(CoverPolicyError, match="non-public"):
        validate_public_addresses(["93.184.216.34", "10.1.2.3"])


def test_userinfo_bad_scheme_and_nonstandard_port_are_blocked() -> None:
    for value in (
        "ftp://example.com/cover.jpg",
        "https://user:pass@example.com/cover.jpg",
        "https://example.com:8443/cover.jpg",
        "http://example.com:8080/cover.jpg",
    ):
        with pytest.raises(CoverPolicyError):
            parse_cover_url(value)


def test_public_redirect_to_private_target_is_blocked_before_second_request() -> None:
    calls: list[tuple[str, str]] = []

    def resolver(host: str, _port: int) -> list[str]:
        return {
            "public.example": ["93.184.216.34"],
            "internal.example": ["169.254.169.254"],
        }[host]

    def request_once(parsed, connect_ip: str, **_kwargs: Any):
        calls.append((parsed.hostname or "", connect_ip))
        return 302, {"location": "http://internal.example/latest/meta-data"}, b""

    with pytest.raises(CoverPolicyError, match="non-public"):
        fetch_public_cover_sync(
            "https://public.example/cover.jpg",
            resolver=resolver,
            request_once=request_once,
        )
    assert calls == [("public.example", "93.184.216.34")]


def test_request_is_bound_to_validated_ip_without_second_dns_lookup() -> None:
    resolver_calls = 0
    seen: list[tuple[str, str]] = []

    def resolver(_host: str, _port: int) -> list[str]:
        nonlocal resolver_calls
        resolver_calls += 1
        if resolver_calls > 1:
            return ["127.0.0.1"]
        return ["93.184.216.34"]

    def request_once(parsed, connect_ip: str, **_kwargs: Any):
        seen.append((parsed.hostname or "", connect_ip))
        return 200, {"content-type": "image/jpeg"}, b"jpeg"

    response = fetch_public_cover_sync(
        "https://public.example/cover.jpg",
        resolver=resolver,
        request_once=request_once,
    )
    assert response.data == b"jpeg"
    assert resolver_calls == 1
    assert seen == [("public.example", "93.184.216.34")]


def test_normal_public_https_image_succeeds() -> None:
    def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def request_once(parsed, connect_ip: str, **_kwargs: Any):
        assert parsed.scheme == "https"
        assert connect_ip == "93.184.216.34"
        return 200, {"content-type": "image/png; charset=binary"}, b"png"

    response = fetch_public_cover_sync(
        "https://public.example/a.png",
        resolver=resolver,
        request_once=request_once,
    )
    assert response.data == b"png"
    assert response.content_type == "image/png"


def test_redirect_limit_fails_closed() -> None:
    def resolver(_host: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    def request_once(_parsed, _connect_ip: str, **_kwargs: Any):
        return 302, {"location": "/again"}, b""

    with pytest.raises(CoverFetchError, match="redirect limit"):
        fetch_public_cover_sync(
            "https://public.example/start",
            max_redirects=1,
            resolver=resolver,
            request_once=request_once,
        )


@pytest.mark.asyncio
async def test_secure_client_surfaces_policy_rejection(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def blocked(*_args: Any, **_kwargs: Any) -> CoverResponse:
        raise CoverPolicyError("cover host resolved to a non-public address")

    monkeypatch.setattr("traxx_mcp.secure_client.fetch_public_cover", blocked)
    client = SecureTraxxClient(
        RuntimeConfig(base_url="https://traxx.example"),
        downloads_dir=tmp_path,
    )

    with pytest.raises(TraxxError, match="Unsafe album cover URL refused"):
        await client._load_cover(tmp_path, "http://169.254.169.254/latest/meta-data")


@pytest.mark.asyncio
async def test_secure_client_preserves_best_effort_public_fetch_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(*_args: Any, **_kwargs: Any) -> CoverResponse:
        raise CoverFetchError("public image unavailable")

    monkeypatch.setattr("traxx_mcp.secure_client.fetch_public_cover", unavailable)
    client = SecureTraxxClient(
        RuntimeConfig(base_url="https://traxx.example"),
        downloads_dir=tmp_path,
    )

    assert await client._load_cover(tmp_path, "https://images.example/cover.jpg") == (
        None,
        "image/jpeg",
        None,
    )


@pytest.mark.asyncio
async def test_secure_client_persists_safe_remote_cover(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fetched(*_args: Any, **_kwargs: Any) -> CoverResponse:
        return CoverResponse(
            data=b"png-data",
            content_type="image/png",
            final_url="https://images.example/cover.png",
        )

    monkeypatch.setattr("traxx_mcp.secure_client.fetch_public_cover", fetched)
    client = SecureTraxxClient(
        RuntimeConfig(base_url="https://traxx.example"),
        downloads_dir=tmp_path,
    )

    data, mime, saved = await client._load_cover(
        tmp_path,
        "https://images.example/cover.png",
    )
    assert data == b"png-data"
    assert mime == "image/png"
    assert saved == tmp_path / "cover.png"
    assert saved.read_bytes() == b"png-data"
