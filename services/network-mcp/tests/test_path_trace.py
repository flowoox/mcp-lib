from __future__ import annotations

import subprocess

import pytest

from network_mcp.path_trace import (
    PathTraceConfig,
    PathTracer,
    build_trace_command,
    parse_trace_output,
)
from network_mcp.policy import AuthorizedTarget


def test_linux_command_uses_numeric_destination_and_fixed_flags_only() -> None:
    command = build_trace_command(
        "/usr/bin/traceroute",
        "10.20.30.40",
        max_hops=12,
        hop_timeout_seconds=1.5,
        system_name="Linux",
    )
    assert command == [
        "/usr/bin/traceroute",
        "-4",
        "-n",
        "-m",
        "12",
        "-w",
        "1.5",
        "-q",
        "1",
        "10.20.30.40",
    ]
    assert all("app.local" not in item for item in command)


def test_windows_command_disables_reverse_dns_and_bounds_timeout() -> None:
    command = build_trace_command(
        "C:/Windows/System32/tracert.exe",
        "2001:db8::10",
        max_hops=15,
        hop_timeout_seconds=0.8,
        system_name="Windows",
    )
    assert command == [
        "C:/Windows/System32/tracert.exe",
        "-d",
        "-h",
        "15",
        "-w",
        "800",
        "2001:db8::10",
    ]


def test_command_rejects_non_allowlisted_executable_and_non_ip_destination() -> None:
    with pytest.raises(ValueError, match="unsupported traceroute executable"):
        build_trace_command(
            "/bin/sh",
            "10.0.0.1",
            max_hops=5,
            hop_timeout_seconds=1.0,
            system_name="Linux",
        )
    with pytest.raises(ValueError):
        build_trace_command(
            "/usr/bin/traceroute",
            "host.example",
            max_hops=5,
            hop_timeout_seconds=1.0,
            system_name="Linux",
        )


def test_parser_returns_only_bounded_structured_hop_evidence() -> None:
    output = """
traceroute to 10.0.0.3 (10.0.0.3), 5 hops max
 1  10.0.0.1  0.5 ms
 2  *
 3  10.0.0.3  1.2 ms
 99  203.0.113.1  9 ms
"""
    parsed = parse_trace_output(output, destination="10.0.0.3", max_hops=5)
    assert parsed["reachedDestination"] is True
    assert parsed["hopCount"] == 3
    assert parsed["hops"] == [
        {
            "hop": 1,
            "addresses": ["10.0.0.1"],
            "timedOut": False,
            "reachedDestination": False,
        },
        {
            "hop": 2,
            "addresses": [],
            "timedOut": True,
            "reachedDestination": False,
        },
        {
            "hop": 3,
            "addresses": ["10.0.0.3"],
            "timedOut": False,
            "reachedDestination": True,
        },
    ]


def test_tracer_runs_shell_false_against_first_authorized_numeric_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="1  10.0.0.1  0.3 ms\n2  10.0.0.2  0.5 ms\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    tracer = PathTracer(
        executable="/usr/bin/traceroute",
        system_name="Linux",
        config=PathTraceConfig(max_hops_limit=20, process_timeout_seconds=10),
    )
    target = AuthorizedTarget(
        requested_host="app.local",
        normalized_host="app.local",
        addresses=("10.0.0.2", "10.0.0.3"),
    )
    result = tracer.trace(target, max_hops=8, hop_timeout_seconds=1.0)
    args = captured["args"]
    assert isinstance(args, list)
    assert args[-1] == "10.0.0.2"
    assert "app.local" not in args
    assert captured["shell"] is False
    assert captured["timeout"] == 10
    assert result["selectedAddress"] == "10.0.0.2"
    assert result["reachedDestination"] is True
    assert "stdout" not in result


def test_trace_bounds_hops_and_probe_timeout_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess must not run for invalid bounds")

    monkeypatch.setattr(subprocess, "run", forbidden_run)
    tracer = PathTracer(
        executable="/usr/bin/traceroute",
        system_name="Linux",
        config=PathTraceConfig(max_hops_limit=12, process_timeout_seconds=10),
    )
    target = AuthorizedTarget("app.local", "app.local", ("10.0.0.2",))
    with pytest.raises(ValueError, match="max_hops"):
        tracer.trace(target, max_hops=13, hop_timeout_seconds=1.0)
    with pytest.raises(ValueError, match="hop_timeout_seconds"):
        tracer.trace(target, max_hops=10, hop_timeout_seconds=10.0)
