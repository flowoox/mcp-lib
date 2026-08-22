from __future__ import annotations

import socket

import pytest

from network_mcp.diagnostics import (
    diagnostic_bundle,
    route_selection_address,
    subnet_validation,
    tcp_probe,
)
from network_mcp.policy import AuthorizedTarget, TargetPolicy


class FakeTcpSocket:
    def __init__(self, family: int, socket_type: int):
        self.family = family
        self.socket_type = socket_type
        self.timeout: float | None = None
        self.target: tuple[object, ...] | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect_ex(self, target: tuple[object, ...]) -> int:
        self.target = target
        return 0 if target[0] == "10.0.0.10" else 111

    def close(self) -> None:
        self.closed = True


class FakeUdpSocket:
    def __init__(self, family: int, socket_type: int):
        self.family = family
        self.socket_type = socket_type
        self.target: tuple[object, ...] | None = None

    def connect(self, target: tuple[object, ...]) -> None:
        self.target = target

    def getsockname(self) -> tuple[object, ...]:
        if self.family == socket.AF_INET6:
            return ("fd00::5", 40000, 0, 0)
        return ("10.0.0.5", 40000)

    def close(self) -> None:
        pass


def test_tcp_probe_connects_to_authorized_ip_not_original_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[FakeTcpSocket] = []

    def fake_socket(family: int, socket_type: int) -> FakeTcpSocket:
        item = FakeTcpSocket(family, socket_type)
        created.append(item)
        return item

    monkeypatch.setattr(socket, "socket", fake_socket)
    target = AuthorizedTarget(
        requested_host="app.local",
        normalized_host="app.local",
        addresses=("10.0.0.10", "10.0.0.11"),
    )
    result = tcp_probe(target, 443, timeout_seconds=1.5)
    assert result["reachable"] is True
    assert [item.target for item in created] == [("10.0.0.10", 443), ("10.0.0.11", 443)]
    assert all(item.timeout == 1.5 for item in created)
    assert all(item.closed for item in created)


def test_route_selection_uses_kernel_udp_route_hint_without_sending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[FakeUdpSocket] = []

    def fake_socket(family: int, socket_type: int) -> FakeUdpSocket:
        item = FakeUdpSocket(family, socket_type)
        created.append(item)
        return item

    monkeypatch.setattr(socket, "socket", fake_socket)
    result = route_selection_address("10.0.0.10")
    assert result == {
        "address": "10.0.0.10",
        "family": "ipv4",
        "routeAvailable": True,
        "selectedSourceAddress": "10.0.0.5",
    }
    assert created[0].target == ("10.0.0.10", 9)


def test_subnet_validation_handles_membership_family_and_properties() -> None:
    inside = subnet_validation("10.20.30.40", "10.20.0.0/16")
    assert inside["network"] == "10.20.0.0/16"
    assert inside["isMember"] is True
    assert inside["sameFamily"] is True
    assert inside["prefixLength"] == 16

    mixed = subnet_validation("2001:db8::1", "10.20.0.0/16")
    assert mixed["sameFamily"] is False
    assert mixed["isMember"] is False


def test_diagnostic_bundle_bounds_ports_and_resolves_once(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = TargetPolicy("10.0.0.0/8")
    calls = 0

    def fake_resolve(host: str) -> AuthorizedTarget:
        nonlocal calls
        calls += 1
        return AuthorizedTarget(host, "app.local", ("10.0.0.10",))

    monkeypatch.setattr(policy, "resolve", fake_resolve)
    monkeypatch.setattr(
        "network_mcp.diagnostics.tcp_probe",
        lambda target, port, timeout_seconds: {
            "requestedHost": target.requested_host,
            "normalizedHost": target.normalized_host,
            "port": port,
            "reachable": True,
            "probes": [],
        },
    )
    monkeypatch.setattr(
        "network_mcp.diagnostics.route_selection",
        lambda target: {"requestedHost": target.requested_host, "routeAvailable": True},
    )

    result = diagnostic_bundle(
        policy,
        "app.local",
        [443, 443, 8443],
        timeout_seconds=1.0,
        max_ports=4,
    )
    assert calls == 1
    assert [item["port"] for item in result["tcp"]] == [443, 8443]

    with pytest.raises(ValueError, match="configured maximum"):
        diagnostic_bundle(
            policy,
            "app.local",
            [1, 2, 3, 4, 5],
            timeout_seconds=1.0,
            max_ports=4,
        )
