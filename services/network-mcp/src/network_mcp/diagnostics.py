from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any

from .policy import AuthorizedTarget, TargetPolicy, validate_port


def dns_result(target: AuthorizedTarget) -> dict[str, Any]:
    return {
        "requestedHost": target.requested_host,
        "normalizedHost": target.normalized_host,
        "addresses": list(target.addresses),
        "addressCount": len(target.addresses),
    }


def _socket_address(address: str, port: int) -> tuple[Any, ...]:
    parsed = ipaddress.ip_address(address)
    if parsed.version == 6:
        return (address, port, 0, 0)
    return (address, port)


def tcp_probe_address(address: str, port: int, *, timeout_seconds: float) -> dict[str, Any]:
    port = validate_port(port)
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    started = time.monotonic()
    error_code: int | None = None
    error_text: str | None = None
    reachable = False
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_seconds)
        error_code = sock.connect_ex(_socket_address(address, port))
        reachable = error_code == 0
        if error_code:
            error_text = "connection failed"
    except OSError:
        error_text = "socket error"
    finally:
        sock.close()
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    return {
        "address": str(parsed),
        "family": "ipv6" if parsed.version == 6 else "ipv4",
        "port": port,
        "reachable": reachable,
        "elapsedMs": elapsed_ms,
        "errorCode": error_code,
        "error": error_text,
    }


def tcp_probe(
    target: AuthorizedTarget,
    port: int,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    port = validate_port(port)
    probes = [
        tcp_probe_address(address, port, timeout_seconds=timeout_seconds)
        for address in target.addresses
    ]
    return {
        "requestedHost": target.requested_host,
        "normalizedHost": target.normalized_host,
        "port": port,
        "reachable": any(item["reachable"] for item in probes),
        "probes": probes,
    }


def route_selection_address(address: str) -> dict[str, Any]:
    """Ask the local kernel which source address it would select without sending a datagram."""

    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.connect(_socket_address(address, 9))
        local = sock.getsockname()
        source = str(local[0])
        return {
            "address": str(parsed),
            "family": "ipv6" if parsed.version == 6 else "ipv4",
            "routeAvailable": True,
            "selectedSourceAddress": source,
        }
    except OSError:
        return {
            "address": str(parsed),
            "family": "ipv6" if parsed.version == 6 else "ipv4",
            "routeAvailable": False,
            "selectedSourceAddress": None,
        }
    finally:
        sock.close()


def route_selection(target: AuthorizedTarget) -> dict[str, Any]:
    selections = [route_selection_address(address) for address in target.addresses]
    return {
        "requestedHost": target.requested_host,
        "normalizedHost": target.normalized_host,
        "routeAvailable": any(item["routeAvailable"] for item in selections),
        "selections": selections,
        "note": "Source-address selection is a bounded kernel route hint; this tool does not run traceroute or arbitrary commands.",
    }


def subnet_validation(address: str, network: str) -> dict[str, Any]:
    try:
        parsed_address = ipaddress.ip_address(address.strip())
    except ValueError as exc:
        raise ValueError("address must be a valid IPv4 or IPv6 address") from exc
    try:
        parsed_network = ipaddress.ip_network(network.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("network must be a valid IPv4 or IPv6 CIDR") from exc
    same_family = parsed_address.version == parsed_network.version
    member = same_family and parsed_address in parsed_network
    return {
        "address": str(parsed_address),
        "network": str(parsed_network),
        "addressFamily": f"ipv{parsed_address.version}",
        "networkFamily": f"ipv{parsed_network.version}",
        "sameFamily": same_family,
        "isMember": member,
        "networkAddress": str(parsed_network.network_address),
        "broadcastAddress": (
            str(parsed_network.broadcast_address) if parsed_network.version == 4 else None
        ),
        "prefixLength": parsed_network.prefixlen,
        "numAddresses": parsed_network.num_addresses,
        "isPrivate": parsed_address.is_private,
        "isLoopback": parsed_address.is_loopback,
        "isLinkLocal": parsed_address.is_link_local,
        "isMulticast": parsed_address.is_multicast,
    }


def diagnostic_bundle(
    policy: TargetPolicy,
    host: str,
    ports: list[int],
    *,
    timeout_seconds: float,
    max_ports: int,
) -> dict[str, Any]:
    if not ports:
        raise ValueError("ports must contain at least one TCP port")
    if len(ports) > max_ports:
        raise ValueError(f"ports exceeds configured maximum of {max_ports}")
    normalized_ports: list[int] = []
    seen: set[int] = set()
    for port in ports:
        validated = validate_port(port)
        if validated not in seen:
            seen.add(validated)
            normalized_ports.append(validated)
    target = policy.resolve(host)
    return {
        "dns": dns_result(target),
        "route": route_selection(target),
        "tcp": [
            tcp_probe(target, port, timeout_seconds=timeout_seconds)
            for port in normalized_ports
        ],
    }
