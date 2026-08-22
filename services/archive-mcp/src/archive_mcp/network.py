from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from urllib.parse import urlsplit

ARCHIVE_ORIGIN = "https://archive.org"
ARCHIVE_HOST = "archive.org"
MAX_REDIRECTS = 5
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


class ArchiveOutboundError(ValueError):
    """Raised when an outbound Archive request violates the network policy."""


def _parsed_https_url(value: str):
    raw = (value or "").strip()
    if not raw:
        raise ArchiveOutboundError("Archive URL must not be empty")
    parsed = urlsplit(raw)
    if parsed.scheme.casefold() != "https":
        raise ArchiveOutboundError("Archive requests require HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ArchiveOutboundError("Archive URLs must not contain userinfo")
    if not parsed.hostname:
        raise ArchiveOutboundError("Archive URL has no hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ArchiveOutboundError("Archive URL contains an invalid port") from exc
    if port not in {None, 443}:
        raise ArchiveOutboundError("Archive requests are restricted to HTTPS port 443")
    return parsed


def normalize_archive_base_url(value: str) -> str:
    """Return the one supported Archive API origin.

    ``archive-mcp`` is an Internet Archive connector, not a generic HTTP
    fetcher. Keeping the configured origin fixed removes the attacker-controlled
    DNS/redirect trust boundary that originally made ``configure_archive`` an
    SSRF primitive while retaining the parameter for backwards-compatible
    clients.
    """

    parsed = _parsed_https_url(value or ARCHIVE_ORIGIN)
    if parsed.hostname.casefold() != ARCHIVE_HOST:
        raise ArchiveOutboundError("Only https://archive.org is supported")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ArchiveOutboundError("Archive base URL must be the bare archive.org origin")
    return ARCHIVE_ORIGIN


def validate_archive_url_syntax(value: str) -> str:
    """Validate one concrete request/redirect URL and return its hostname.

    Internet Archive downloads legitimately redirect to storage nodes below
    ``*.archive.org``. Those hosts are permitted, while redirects to unrelated
    hosts, IP literals, alternative schemes, userinfo and non-443 ports fail
    closed before a request is sent.
    """

    parsed = _parsed_https_url(value)
    host = parsed.hostname.casefold()
    if host != ARCHIVE_HOST and not host.endswith(f".{ARCHIVE_HOST}"):
        raise ArchiveOutboundError("Archive redirects must stay on archive.org hosts")
    return host


def validate_resolved_addresses(addresses: Iterable[str]) -> None:
    """Reject any DNS answer that is not safe for public Internet egress.

    Blocking the complete answer set prevents a mixed public/private DNS reply
    from being treated as safe. IPv4-mapped IPv6 is normalized before the
    classification so ``::ffff:127.0.0.1`` cannot bypass the IPv4 policy.

    ``ipaddress.is_global`` alone is intentionally insufficient: Python treats
    multicast addresses as global in some versions, but multicast is never a
    valid destination for this HTTP connector.
    """

    seen = False
    for raw in addresses:
        value = str(raw).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ArchiveOutboundError(
                f"Archive host resolved to an invalid address: {raw}"
            ) from exc
        seen = True
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
            raise ArchiveOutboundError(
                f"Archive host resolved to a non-public address: {address.compressed}"
            )
    if not seen:
        raise ArchiveOutboundError("Archive hostname did not resolve to any address")


async def _default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        answers = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise ArchiveOutboundError(f"Archive hostname could not be resolved: {host}") from exc
    return sorted({str(answer[4][0]) for answer in answers})


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def validate_archive_outbound_url(
    value: str,
    *,
    resolver: Resolver = _default_resolver,
) -> None:
    """Validate scheme/host and the complete current DNS answer set.

    A DNS lookup still necessarily precedes the HTTP client's own connect-time
    lookup. The important trust reduction here is that callers can no longer
    choose a hostname: only ``archive.org`` and its storage-node subdomains are
    accepted. The address check additionally fails closed if those trusted
    names ever resolve to loopback, private, link-local, multicast, reserved or
    otherwise non-global IPv4/IPv6 addresses.
    """

    host = validate_archive_url_syntax(value)
    addresses = await resolver(host, 443)
    validate_resolved_addresses(addresses)


__all__ = [
    "ARCHIVE_HOST",
    "ARCHIVE_ORIGIN",
    "ArchiveOutboundError",
    "MAX_REDIRECTS",
    "REDIRECT_STATUS_CODES",
    "normalize_archive_base_url",
    "validate_archive_outbound_url",
    "validate_archive_url_syntax",
    "validate_resolved_addresses",
]
