from __future__ import annotations

import socket

import pytest

from network_mcp.policy import TargetPolicy, TargetPolicyError, normalize_host, validate_port


def test_normalize_host_accepts_bare_host_or_ip_and_rejects_urls_paths() -> None:
    assert normalize_host(" Example.LOCAL. ") == "example.local"
    assert normalize_host("127.0.0.1") == "127.0.0.1"
    for value in ("https://example.local", "example.local/path", "user@example.local", "bad host"):
        with pytest.raises(ValueError):
            normalize_host(value)


def test_policy_defaults_can_be_narrow_and_reject_mixed_resolution() -> None:
    policy = TargetPolicy("10.0.0.0/8")
    authorized = policy.authorize_addresses("srv.local", ["10.1.2.3", "10.1.2.3"])
    assert authorized.addresses == ("10.1.2.3",)
    with pytest.raises(TargetPolicyError, match="outside"):
        policy.authorize_addresses("srv.local", ["10.1.2.3", "203.0.113.9"])


def test_resolve_authorizes_all_os_resolver_results(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.5.0.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.5.0.11", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    target = TargetPolicy("10.0.0.0/8").resolve("app.local")
    assert target.normalized_host == "app.local"
    assert target.addresses == ("10.5.0.10", "10.5.0.11")


def test_literal_ip_does_not_require_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_getaddrinfo(*args: object, **kwargs: object) -> None:
        raise AssertionError("DNS must not be called for an IP literal")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    target = TargetPolicy("192.168.0.0/16").resolve("192.168.1.10")
    assert target.addresses == ("192.168.1.10",)


def test_policy_fails_closed_on_empty_or_excessive_target_set() -> None:
    with pytest.raises(ValueError, match="at least one CIDR"):
        TargetPolicy("")
    policy = TargetPolicy("10.0.0.0/8", max_addresses=1)
    with pytest.raises(LookupError):
        policy.authorize_addresses("app.local", [])
    with pytest.raises(TargetPolicyError, match="too many"):
        policy.authorize_addresses("app.local", ["10.0.0.1", "10.0.0.2"])


def test_port_validation_rejects_ranges_and_boolean_values() -> None:
    assert validate_port(443) == 443
    for value in (0, 65536, True):
        with pytest.raises(ValueError):
            validate_port(value)
