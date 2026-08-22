from __future__ import annotations

import ipaddress
import os
import platform
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .policy import AuthorizedTarget

_HOP_RE = re.compile(r"^\s*(\d{1,3})\s+(.*)$")
_MAX_CAPTURE_BYTES = 32768
_MAX_ADDRESSES_PER_HOP = 4
_ALLOWED_BASENAMES = {"traceroute", "traceroute.exe", "tracert", "tracert.exe"}
_FIXED_UNIX_CANDIDATES = (
    "/usr/bin/traceroute",
    "/bin/traceroute",
    "/usr/sbin/traceroute",
    "/sbin/traceroute",
)


class PathTraceUnavailableError(RuntimeError):
    """No supported fixed traceroute executable is available on the host."""


class PathTraceOutputLimitError(RuntimeError):
    """The fixed traceroute process exceeded the bounded output contract."""


@dataclass(frozen=True)
class PathTraceConfig:
    max_hops_limit: int = 30
    process_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_hops_limit <= 64:
            raise ValueError("max_hops_limit must be between 1 and 64")
        if not 1.0 <= self.process_timeout_seconds <= 120.0:
            raise ValueError("process_timeout_seconds must be between 1 and 120")


def _system_name(value: str | None = None) -> str:
    return (value or platform.system()).casefold()


def _pure_path(executable: str, system_name: str | None = None) -> PurePosixPath | PureWindowsPath:
    if _system_name(system_name) == "windows":
        return PureWindowsPath(executable)
    return PurePosixPath(executable)


def _validate_executable_path(executable: str, system_name: str | None = None) -> str:
    value = executable.strip()
    path = _pure_path(value, system_name)
    if not value or not path.is_absolute():
        raise ValueError("traceroute executable must be an absolute path")
    if path.name.casefold() not in _ALLOWED_BASENAMES:
        raise ValueError("unsupported traceroute executable")
    return value


def _fixed_candidates(system_name: str | None = None) -> tuple[Path, ...]:
    system = _system_name(system_name)
    if system != "windows":
        return tuple(Path(value) for value in _FIXED_UNIX_CANDIDATES)

    roots: list[str] = []
    for name in ("SystemRoot", "WINDIR"):
        value = os.environ.get(name, "").strip()
        if value and value.casefold() not in {item.casefold() for item in roots}:
            roots.append(value)
    if not roots:
        roots.append(r"C:\Windows")
    return tuple(Path(root) / "System32" / "tracert.exe" for root in roots)


def _supported_executable(system_name: str | None = None) -> str:
    system = _system_name(system_name)
    for candidate in _fixed_candidates(system):
        try:
            _validate_executable_path(str(candidate), system)
            resolved = candidate.resolve(strict=True)
        except (OSError, ValueError):
            continue
        if not resolved.is_file():
            continue
        if os.name != "nt" and not os.access(resolved, os.X_OK):
            continue
        # Execute the fixed absolute system path. Its resolved target was checked
        # above, while retaining the allowlisted basename in argv[0].
        return str(candidate)
    raise PathTraceUnavailableError("no supported fixed traceroute executable is installed")


def _validate_trace_args(
    max_hops: int,
    hop_timeout_seconds: float,
    *,
    config: PathTraceConfig,
) -> None:
    if isinstance(max_hops, bool) or not 1 <= max_hops <= config.max_hops_limit:
        raise ValueError(f"max_hops must be between 1 and {config.max_hops_limit}")
    if isinstance(hop_timeout_seconds, bool) or not 0.2 <= hop_timeout_seconds <= 5.0:
        raise ValueError("hop_timeout_seconds must be between 0.2 and 5.0")


def build_trace_command(
    executable: str,
    address: str,
    *,
    max_hops: int,
    hop_timeout_seconds: float,
    system_name: str | None = None,
) -> list[str]:
    """Build a static argv for one authorized numeric destination.

    The executable is runtime-resolved from fixed system paths and the
    destination must already be a numeric IP. No caller-supplied flags, host
    names, shell fragments or relative executables can enter the command.
    """

    system = _system_name(system_name)
    executable = _validate_executable_path(executable, system)
    parsed = ipaddress.ip_address(address)
    if system == "windows":
        timeout_ms = max(200, int(round(hop_timeout_seconds * 1000)))
        return [
            executable,
            "-d",
            "-h",
            str(max_hops),
            "-w",
            str(timeout_ms),
            str(parsed),
        ]
    family_flag = "-6" if parsed.version == 6 else "-4"
    return [
        executable,
        family_flag,
        "-n",
        "-m",
        str(max_hops),
        "-w",
        f"{hop_timeout_seconds:.1f}",
        "-q",
        "1",
        str(parsed),
    ]


def _ip_tokens(text: str, *, limit: int = _MAX_ADDRESSES_PER_HOP) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    for token in text.split():
        candidate = token.strip("()[]<>,;")
        if not candidate:
            continue
        try:
            rendered = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if rendered not in seen:
            seen.add(rendered)
            addresses.append(rendered)
            if len(addresses) >= limit:
                break
    return addresses


def parse_trace_output(text: str, *, destination: str, max_hops: int) -> dict[str, Any]:
    destination_ip = str(ipaddress.ip_address(destination))
    hops: list[dict[str, Any]] = []
    seen_hops: set[int] = set()
    for raw_line in text.splitlines():
        match = _HOP_RE.match(raw_line)
        if not match:
            continue
        hop = int(match.group(1))
        if not 1 <= hop <= max_hops or hop in seen_hops:
            continue
        seen_hops.add(hop)
        body = match.group(2)
        addresses = _ip_tokens(body)
        hops.append(
            {
                "hop": hop,
                "addresses": addresses,
                "timedOut": not addresses,
                "reachedDestination": destination_ip in addresses,
            }
        )
    reached = any(item["reachedDestination"] for item in hops)
    return {
        "destinationAddress": destination_ip,
        "maxHops": max_hops,
        "reachedDestination": reached,
        "hopCount": len(hops),
        "hops": hops,
    }


def _child_environment(system_name: str) -> dict[str, str]:
    if _system_name(system_name) == "windows":
        return {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR")
            if name in os.environ
        }
    return {"LANG": "C", "LC_ALL": "C"}


class PathTracer:
    """Run one fixed, bounded traceroute against one already-authorized IP address."""

    def __init__(
        self,
        *,
        config: PathTraceConfig | None = None,
        executable: str | None = None,
        system_name: str | None = None,
    ) -> None:
        self.config = config or PathTraceConfig()
        self.system_name = system_name or platform.system()
        discovered = executable or _supported_executable(self.system_name)
        self.executable = _validate_executable_path(discovered, self.system_name)
        self.working_directory = str(_pure_path(self.executable, self.system_name).parent)

    def trace(
        self,
        target: AuthorizedTarget,
        *,
        max_hops: int,
        hop_timeout_seconds: float,
    ) -> dict[str, Any]:
        _validate_trace_args(max_hops, hop_timeout_seconds, config=self.config)
        if not target.addresses:
            raise ValueError("authorized target has no addresses")
        destination = target.addresses[0]
        command = build_trace_command(
            self.executable,
            destination,
            max_hops=max_hops,
            hop_timeout_seconds=hop_timeout_seconds,
            system_name=self.system_name,
        )
        env = _child_environment(self.system_name)
        try:
            with tempfile.TemporaryFile(mode="w+b") as capture:
                completed = subprocess.run(
                    command,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=capture,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=self.config.process_timeout_seconds,
                    env=env,
                    cwd=self.working_directory,
                    close_fds=True,
                )
                capture.seek(0, os.SEEK_END)
                captured_bytes = capture.tell()
                if captured_bytes > _MAX_CAPTURE_BYTES:
                    raise PathTraceOutputLimitError(
                        "path trace exceeded the bounded 32 KiB output contract"
                    )
                capture.seek(0)
                raw_output = capture.read(_MAX_CAPTURE_BYTES)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("path trace exceeded the configured process timeout") from exc
        except OSError as exc:
            raise PathTraceUnavailableError(
                "unable to start the supported traceroute executable"
            ) from exc

        stdout = raw_output.decode("utf-8", errors="replace")
        parsed = parse_trace_output(stdout, destination=destination, max_hops=max_hops)
        parsed.update(
            {
                "requestedHost": target.requested_host,
                "normalizedHost": target.normalized_host,
                "selectedAddress": destination,
                "addressSelection": "first-authorized-resolver-result",
                "exitCode": completed.returncode,
                "capturedBytes": captured_bytes,
                "commandMode": "fixed-absolute-argv-no-shell-numeric-destination",
            }
        )
        return parsed
