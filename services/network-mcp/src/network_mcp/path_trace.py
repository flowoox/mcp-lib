from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import AuthorizedTarget

_HOP_RE = re.compile(r"^\s*(\d{1,3})\s+(.*)$")
_MAX_CAPTURE_BYTES = 32768
_ALLOWED_BASENAMES = {"traceroute", "traceroute.exe", "tracert", "tracert.exe"}


class PathTraceUnavailableError(RuntimeError):
    """No supported fixed traceroute executable is available on the host."""


@dataclass(frozen=True)
class PathTraceConfig:
    max_hops_limit: int = 30
    process_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_hops_limit <= 64:
            raise ValueError("max_hops_limit must be between 1 and 64")
        if not 1.0 <= self.process_timeout_seconds <= 120.0:
            raise ValueError("process_timeout_seconds must be between 1 and 120")


def _supported_executable(system_name: str | None = None) -> str:
    system = (system_name or platform.system()).casefold()
    candidates = ("tracert.exe", "tracert") if system == "windows" else ("traceroute",)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if not resolved:
            continue
        basename = Path(resolved).name.casefold()
        if basename not in _ALLOWED_BASENAMES:
            continue
        return str(Path(resolved).resolve())
    raise PathTraceUnavailableError("no supported traceroute executable is installed")


def _validate_trace_args(max_hops: int, hop_timeout_seconds: float, *, config: PathTraceConfig) -> None:
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

    The executable is runtime-resolved from a fixed allowlist and the destination
    must already be a numeric IP. No caller-supplied flags or shell fragments can
    enter the command.
    """

    basename = Path(executable).name.casefold()
    if basename not in _ALLOWED_BASENAMES:
        raise ValueError("unsupported traceroute executable")
    parsed = ipaddress.ip_address(address)
    system = (system_name or platform.system()).casefold()
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


def _ip_tokens(text: str) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    for token in text.split():
        candidate = token.strip("()[]<>,;:")
        if not candidate:
            continue
        try:
            rendered = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if rendered not in seen:
            seen.add(rendered)
            addresses.append(rendered)
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
        self.executable = executable or _supported_executable(self.system_name)
        basename = Path(self.executable).name.casefold()
        if basename not in _ALLOWED_BASENAMES:
            raise ValueError("unsupported traceroute executable")

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
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=self.config.process_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("path trace exceeded the configured process timeout") from exc
        except OSError as exc:
            raise PathTraceUnavailableError("unable to start the supported traceroute executable") from exc

        stdout = (completed.stdout or "").encode("utf-8", errors="replace")[:_MAX_CAPTURE_BYTES].decode(
            "utf-8", errors="replace"
        )
        parsed = parse_trace_output(stdout, destination=destination, max_hops=max_hops)
        parsed.update(
            {
                "requestedHost": target.requested_host,
                "normalizedHost": target.normalized_host,
                "selectedAddress": destination,
                "addressSelection": "first-authorized-resolver-result",
                "exitCode": completed.returncode,
                "commandMode": "fixed-argv-no-shell-numeric-destination",
            }
        )
        return parsed
