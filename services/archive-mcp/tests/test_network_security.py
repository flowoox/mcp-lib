from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archive_mcp.client import ArchiveError
from archive_mcp.config import RuntimeConfig
from archive_mcp.network import (
    ARCHIVE_ORIGIN,
    ArchiveOutboundError,
    validate_archive_outbound_url,
    validate_archive_url_syntax,
    validate_resolved_addresses,
)
from archive_mcp.secure_client import SecureArchiveClient


@pytest.mark.parametrize(
    "value",
    [
        "http://archive.org",
        "ftp://archive.org",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://archive.org.evil.example",
        "https://user:password@archive.org",
        "https://archive.org:444",
        "https://archive.org/api",
        "https://archive.org/?next=https://127.0.0.1",
    ],
)
def test_runtime_config_rejects_untrusted_base_urls(value: str) -> None:
    with pytest.raises(ValueError):
        RuntimeConfig(base_url=value)


def test_runtime_config_normalizes_the_supported_origin() -> None:
    assert RuntimeConfig(base_url="https://archive.org/").base_url == ARCHIVE_ORIGIN


@pytest.mark.parametrize(
    "url",
    [
        "https://archive.org/metadata/example",
        "https://ia801234.us.archive.org/12/items/example/file.flac",
    ],
)
def test_request_policy_allows_archive_hosts(url: str) -> None:
    validate_archive_url_syntax(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://archive.org/metadata/example",
        "https://evil.example/metadata/example",
        "https://archive.org.evil.example/metadata/example",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://user@archive.org/metadata/example",
        "https://archive.org:8443/metadata/example",
    ],
)
def test_request_policy_rejects_non_archive_targets(url: str) -> None:
    with pytest.raises(ArchiveOutboundError):
        validate_archive_url_syntax(url)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_dns_policy_rejects_non_public_addresses(address: str) -> None:
    with pytest.raises(ArchiveOutboundError):
        validate_resolved_addresses([address])


def test_dns_policy_rejects_mixed_public_private_answers() -> None:
    with pytest.raises(ArchiveOutboundError):
        validate_resolved_addresses(["8.8.8.8", "127.0.0.1"])


def test_dns_policy_accepts_public_ipv4_and_ipv6() -> None:
    validate_resolved_addresses(["8.8.8.8", "2606:4700:4700::1111"])


async def test_dns_rebinding_style_private_answer_is_blocked() -> None:
    async def resolver(host: str, port: int) -> list[str]:
        assert host == "archive.org"
        assert port == 443
        return ["169.254.169.254"]

    with pytest.raises(ArchiveOutboundError):
        await validate_archive_outbound_url(ARCHIVE_ORIGIN, resolver=resolver)


async def _syntax_only_validator(url: str) -> None:
    validate_archive_url_syntax(url)


async def test_redirect_to_metadata_ip_is_blocked_before_second_request(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "archive.org":
            return httpx.Response(
                302,
                headers={"location": "https://169.254.169.254/latest/meta-data"},
            )
        raise AssertionError("redirect target must never be requested")

    client = SecureArchiveClient(
        RuntimeConfig(),
        downloads_dir=tmp_path,
        url_validator=_syntax_only_validator,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ArchiveError, match="blocked"):
        await client.request_json("/metadata/example")
    assert len(seen) == 1


async def test_archive_storage_redirect_is_revalidated_and_allowed(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "archive.org":
            return httpx.Response(
                302,
                headers={"location": "https://ia801234.us.archive.org/metadata/example"},
            )
        assert request.url.host == "ia801234.us.archive.org"
        return httpx.Response(200, json={"ok": True})

    client = SecureArchiveClient(
        RuntimeConfig(),
        downloads_dir=tmp_path,
        url_validator=_syntax_only_validator,
        transport=httpx.MockTransport(handler),
    )
    assert await client.request_json("/metadata/example") == {"ok": True}
    assert len(seen) == 2


async def test_upstream_error_body_is_not_reflected(tmp_path: Path) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(500, text="SECRET_INTERNAL_PROVIDER_DIAGNOSTIC")
    )
    client = SecureArchiveClient(
        RuntimeConfig(),
        downloads_dir=tmp_path,
        url_validator=_syntax_only_validator,
        transport=transport,
    )
    with pytest.raises(ArchiveError) as caught:
        await client.request_json("/metadata/example")
    assert "SECRET_INTERNAL_PROVIDER_DIAGNOSTIC" not in str(caught.value)
