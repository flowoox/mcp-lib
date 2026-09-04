from __future__ import annotations

import asyncio
import http.client
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

MAX_COVER_BYTES = 20 * 1024 * 1024
MAX_REDIRECTS = 5
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


class CoverPolicyError(ValueError):
    """Raised before egress when a cover URL violates the network policy."""


class CoverFetchError(RuntimeError):
    """Raised when an otherwise permitted cover cannot be fetched safely."""


@dataclass(frozen=True)
class CoverResponse:
    data: bytes
    content_type: str
    final_url: str


class Resolver(Protocol):
    def __call__(self, host: str, port: int) -> list[str]: ...


class RequestOnce(Protocol):
    def __call__(
        self,
        parsed: SplitResult,
        connect_ip: str,
        *,
        verify_tls: bool,
        timeout_seconds: float,
        max_bytes: int,
    ) -> tuple[int, dict[str, str], bytes]: ...


def parse_cover_url(value: str) -> SplitResult:
    raw = (value or "").strip()
    if not raw:
        raise CoverPolicyError("cover URL must not be empty")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"}:
        raise CoverPolicyError("cover URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise CoverPolicyError("cover URL must not contain userinfo")
    if not parsed.hostname:
        raise CoverPolicyError("cover URL has no hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise CoverPolicyError("cover URL contains an invalid port") from exc
    allowed_port = 443 if scheme == "https" else 80
    if port not in {None, allowed_port}:
        raise CoverPolicyError(
            f"cover URL {scheme} requests are restricted to port {allowed_port}"
        )
    return parsed


def validate_public_addresses(addresses: Iterable[str]) -> list[str]:
    validated: list[str] = []
    for raw in addresses:
        value = str(raw).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise CoverPolicyError(f"cover host resolved to an invalid address: {raw}") from exc
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
        blocked = (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
        if blocked:
            raise CoverPolicyError(
                f"cover host resolved to a non-public address: {address.compressed}"
            )
        normalized = address.compressed
        if normalized not in validated:
            validated.append(normalized)
    if not validated:
        raise CoverPolicyError("cover hostname did not resolve to any address")
    return validated


def _default_resolver(host: str, port: int) -> list[str]:
    try:
        answers = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise CoverFetchError(f"cover hostname could not be resolved: {host}") from exc
    return sorted({str(answer[4][0]) for answer in answers})


class _BoundHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_ip: str, *, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class _BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        connect_ip: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _read_limited(response: http.client.HTTPResponse, max_bytes: int) -> bytes:
    content_length = response.getheader("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            declared = -1
        if declared > max_bytes:
            raise CoverFetchError(f"album cover exceeds {max_bytes} bytes")
    output = bytearray()
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > max_bytes:
            raise CoverFetchError(f"album cover exceeds {max_bytes} bytes")
    return bytes(output)


def _request_once(
    parsed: SplitResult,
    connect_ip: str,
    *,
    verify_tls: bool,
    timeout_seconds: float,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes]:
    scheme = parsed.scheme.casefold()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    if scheme == "https":
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        connection: http.client.HTTPConnection = _BoundHTTPSConnection(
            host,
            port,
            connect_ip,
            timeout=timeout_seconds,
            context=context,
        )
    else:
        connection = _BoundHTTPConnection(
            host,
            port,
            connect_ip,
            timeout=timeout_seconds,
        )
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Accept": "image/*,*/*;q=0.1",
                "User-Agent": "flowoox-traxx-mcp/cover-fetch",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = {key.casefold(): value for key, value in response.getheaders()}
        if response.status in REDIRECT_STATUS_CODES:
            return response.status, headers, b""
        data = _read_limited(response, max_bytes)
        return response.status, headers, data
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise CoverFetchError(f"cover request failed: {exc}") from exc
    finally:
        connection.close()


def fetch_public_cover_sync(
    value: str,
    *,
    verify_tls: bool = True,
    timeout_seconds: float = 30.0,
    max_bytes: int = MAX_COVER_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    resolver: Resolver = _default_resolver,
    request_once: RequestOnce = _request_once,
) -> CoverResponse:
    current = (value or "").strip()
    for redirect_count in range(max_redirects + 1):
        parsed = parse_cover_url(current)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
        addresses = validate_public_addresses(resolver(host, port))
        # The actual socket is opened to this exact already-validated address,
        # while Host and TLS SNI keep using the original hostname. There is no
        # second DNS lookup between authorization and connect, closing the
        # usual DNS-rebinding/TOCTOU gap.
        connect_ip = addresses[0]
        status, headers, data = request_once(
            parsed,
            connect_ip,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
        )
        if status in REDIRECT_STATUS_CODES:
            location = headers.get("location", "").strip()
            if not location:
                raise CoverFetchError("cover redirect did not include Location")
            if redirect_count >= max_redirects:
                raise CoverFetchError("cover redirect limit exceeded")
            current = urljoin(current, location)
            continue
        if status < 200 or status >= 300:
            raise CoverFetchError(f"cover request returned HTTP {status}")
        content_type = headers.get("content-type", "").split(";", 1)[0].strip()
        return CoverResponse(data=data, content_type=content_type, final_url=current)
    raise CoverFetchError("cover redirect limit exceeded")


async def fetch_public_cover(
    value: str,
    *,
    verify_tls: bool = True,
    timeout_seconds: float = 30.0,
    max_bytes: int = MAX_COVER_BYTES,
    max_redirects: int = MAX_REDIRECTS,
) -> CoverResponse:
    return await asyncio.to_thread(
        fetch_public_cover_sync,
        value,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
    )


__all__ = [
    "CoverFetchError",
    "CoverPolicyError",
    "CoverResponse",
    "MAX_COVER_BYTES",
    "MAX_REDIRECTS",
    "fetch_public_cover",
    "fetch_public_cover_sync",
    "parse_cover_url",
    "validate_public_addresses",
]
