from __future__ import annotations

import subprocess
from typing import Any

import pytest

from network_mcp.path_trace import (
    PathTraceConfig,
    PathTraceOutputLimitError,
    PathTracer,
    _fixed_candidates,
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


def test_command_rejects_relative_non_allowlisted_or_non_ip_inputs() -> None:
    with pytest.raises(ValueError, match="unsupported traceroute executable"):
        build_trace_command(
            "/bin/sh",
            "10.0.0.1",
            max_hops=5,
            hop_timeout_seconds=1.0,
            system_name="Linux",
        )
    with pytest.raises(ValueError, match="absolute path"):
        build_trace_command(
            "traceroute",
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


def test_discovery_uses_fixed_system_paths_not_path_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "/tmp/model-controlled-bin")
    candidates = tuple(str(item) for item in _fixed_candidates("Linux"))
    assert candidates == (
        "/usr/bin/traceroute",
        "/bin/traceroute",
        "/usr/sbin/traceroute",
        "/sbin/traceroute",
    )
    assert all("model-controlled-bin" not in item for item in candidates)


def test_parser_returns_only_bounded_structured_hop_evidence() -> None:
    output = """
traceroute to 10.0.0.3 (10.0.0.3), 5 hops max
 1  10.0.0.1  0.5 ms
 2  *
 3  10.0.0.3  1.2 ms
 4  192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5
 99  203.0.113.1  9 ms
"""
    parsed = parse_trace_output(output, destination="10.0.0.3", max_hops=5)
    assert parsed["reachedDestination"] is True
    assert parsed["hopCount"] == 4
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
        {
            "hop": 4,
            "addresses": ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
            "timedOut": False,
            "reachedDestination": False,
        },
    ]


def _fake_completed_process(
    captured: dict[str, Any],
    stdout_bytes: bytes,
    *,
    returncode: int = 0,
):
    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["args"] = args
        captured.update(kwargs)
        output = kwargs["stdout"]
        output.write(stdout_bytes)
        output.flush()
        return subprocess.CompletedProcess(args=args, returncode=returncode)

    return fake_run


def test_tracer_runs_with_closed_input_suppressed_stderr_and_bounded_file_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_completed_process(
            captured,
            b"1  10.0.0.1  0.3 ms\n2  10.0.0.2  0.5 ms\n",
        ),
    )
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
    assert captured["stdin"] == subprocess.DEVNULL
    assert captured["stderr"] == subprocess.DEVNULL
    assert captured["close_fds"] is True
    assert captured["cwd"] == "/usr/bin"
    assert captured["env"] == {"LANG": "C", "LC_ALL": "C"}
    assert "capture_output" not in captured
    assert result["selectedAddress"] == "10.0.0.2"
    assert result["reachedDestination"] is True
    assert result["capturedBytes"] > 0
    assert "stdout" not in result


def test_trace_rejects_output_above_32_kib_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_completed_process(captured, b"x" * 32769),
    )
    tracer = PathTracer(
        executable="/usr/bin/traceroute",
        system_name="Linux",
        config=PathTraceConfig(max_hops_limit=20, process_timeout_seconds=10),
    )
    target = AuthorizedTarget("app.local", "app.local", ("10.0.0.2",))
    with pytest.raises(PathTraceOutputLimitError, match="32 KiB"):
        tracer.trace(target, max_hops=8, hop_timeout_seconds=1.0)


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
