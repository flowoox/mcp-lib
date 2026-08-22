from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

_HOST_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class TargetPolicyError(PermissionError):
    """The requested network target is outside the configured diagnostic boundary."""


def normalize_host(value: str) -> str:
    host = value.strip()
    if not host:
        raise ValueError("host must not be blank")
    if len(host) > 253:
        raise ValueError("host is too long")
    if any(ord(character) < 33 for character in host):
        raise ValueError("host must not contain whitespace or control characters")
    if any(token in host for token in ("://", "/", "\\", "@", "?", "#")):
        raise ValueError("host must be a bare hostname or IP address, not a URL or path")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("host is not valid IDNA") from exc
    labels = ascii_host.split(".")
    if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("host contains an invalid DNS label")
    return ascii_host.casefold()


def parse_allowed_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid NETWORK_ALLOWED_CIDRS entry: {item}") from exc
        networks.append(network)
    if not networks:
        raise ValueError("NETWORK_ALLOWED_CIDRS must contain at least one CIDR")
    return tuple(networks)


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


@dataclass(frozen=True)
class AuthorizedTarget:
    requested_host: str
    normalized_host: str
    addresses: tuple[str, ...]


class TargetPolicy:
    """Resolve once, then authorize every resulting address before any probe occurs."""

    def __init__(self, allowed_cidrs: str, *, max_addresses: int = 16):
        if not 1 <= max_addresses <= 64:
            raise ValueError("max_addresses must be between 1 and 64")
        self.networks = parse_allowed_networks(allowed_cidrs)
        self.max_addresses = max_addresses

    def _allowed(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(
            address.version == network.version and address in network
            for network in self.networks
        )

    def authorize_addresses(self, host: str, addresses: list[str] | tuple[str, ...]) -> AuthorizedTarget:
        normalized_host = normalize_host(host)
        unique: list[str] = []
        seen: set[str] = set()
        for raw in addresses:
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise ValueError("resolver returned a non-IP address") from exc
            rendered = str(parsed)
            if rendered in seen:
                continue
            seen.add(rendered)
            unique.append(rendered)
        if not unique:
            raise LookupError("target did not resolve to an IP address")
        if len(unique) > self.max_addresses:
            raise TargetPolicyError("target resolved to too many addresses")
        denied = [address for address in unique if not self._allowed(ipaddress.ip_address(address))]
        if denied:
            raise TargetPolicyError(
                "target resolves outside NETWORK_ALLOWED_CIDRS; refusing partial or mixed authorization"
            )
        return AuthorizedTarget(
            requested_host=host,
            normalized_host=normalized_host,
            addresses=tuple(unique),
        )

    def resolve(self, host: str) -> AuthorizedTarget:
        normalized_host = normalize_host(host)
        try:
            literal = ipaddress.ip_address(normalized_host)
        except ValueError:
            literal = None
        if literal is not None:
            return self.authorize_addresses(host, [str(literal)])
        try:
            records = socket.getaddrinfo(
                normalized_host,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise LookupError("target DNS resolution failed") from exc
        addresses = [str(record[4][0]) for record in records]
        return self.authorize_addresses(host, addresses)
