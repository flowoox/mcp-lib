from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from collections.abc import Mapping
from typing import Any

from .config import WindowsTarget
from .scripts import SCRIPTS, ScriptId

_ALLOWED_EXECUTABLES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
_PASSTHROUGH_ENV = ("PATH", "SystemRoot", "WINDIR", "PSModulePath", "TEMP", "TMP")
_MAX_INPUT_BYTES = 32_768
_MAX_ERROR_DETAIL_BYTES = 4_096


class PowerShellExecutionError(RuntimeError):
    """A static Windows diagnostic probe failed or returned invalid bounded JSON."""


class PowerShellRunner:
    """Run repository-owned read-only PowerShell probes locally or through JEA/WinRM.

    No model input is interpolated into PowerShell source or argv. The logical target is
    resolved from deployment configuration before this boundary. Remote execution uses a
    configured constrained endpoint and inherited service identity; credentials are never
    MCP values.
    """

    def __init__(self, executable: str):
        executable = executable.strip()
        if not executable:
            raise ValueError("WINDOWS_POWERSHELL_EXECUTABLE must not be blank")
        basename = executable.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if basename not in _ALLOWED_EXECUTABLES:
            raise ValueError("WINDOWS_POWERSHELL_EXECUTABLE must resolve to PowerShell or pwsh")
        self.executable = executable

    @staticmethod
    def _remote_wrapper(script: str) -> str:
        return f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$payload = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_INPUT')
$target = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_TARGET')
$configuration = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_CONFIGURATION')
if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($configuration)) {{ throw 'Remote target configuration is incomplete' }}
$remoteProbe = {{
  param([string]$payload)
  [Environment]::SetEnvironmentVariable('FLOWOOX_MCP_INPUT', $payload, 'Process')
{script}
}}
$output = @(Invoke-Command -ComputerName $target -ConfigurationName $configuration -Authentication Kerberos -ScriptBlock $remoteProbe -ArgumentList $payload -ErrorAction Stop)
if ($output.Count -ne 1) {{ throw 'Remote diagnostic probe returned an unexpected output shape' }}
[Console]::Out.Write([string]$output[0])
""".strip()

    def run(
        self,
        script_id: ScriptId,
        target: WindowsTarget,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[dict[str, Any], int]:
        try:
            script = SCRIPTS[script_id]
        except KeyError as exc:
            raise ValueError(f"Unknown Windows script id: {script_id}") from exc
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_response_bytes < 1_024:
            raise ValueError("max_response_bytes must be at least 1024")

        payload_json = json.dumps(dict(payload or {}), ensure_ascii=False, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) > _MAX_INPUT_BYTES:
            raise ValueError("Windows diagnostic payload exceeds the fixed input byte limit")

        command = script if target.transport == "local" else self._remote_wrapper(script)
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        env = {name: os.environ[name] for name in _PASSTHROUGH_ENV if name in os.environ}
        env["FLOWOOX_MCP_INPUT"] = payload_json
        if target.transport == "winrm":
            assert target.configuration_name is not None
            env["FLOWOOX_MCP_TARGET"] = target.computer_name
            env["FLOWOOX_MCP_CONFIGURATION"] = target.configuration_name

        argv = [
            self.executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
                mode="w+b"
            ) as stderr_file:
                completed = subprocess.run(
                    argv,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=timeout_seconds,
                    env=env,
                    shell=False,
                    creationflags=creationflags,
                )
                stdout_size = stdout_file.tell()
                stderr_size = stderr_file.tell()
                if stdout_size > max_response_bytes:
                    raise PowerShellExecutionError(
                        "Windows diagnostic probe exceeded the configured response byte limit"
                    )
                stdout_file.seek(0)
                raw = stdout_file.read(max_response_bytes + 1)
                if completed.returncode != 0:
                    stderr_file.seek(max(0, stderr_size - _MAX_ERROR_DETAIL_BYTES))
                    detail = stderr_file.read(_MAX_ERROR_DETAIL_BYTES).decode(
                        "utf-8", errors="replace"
                    )
                    detail = detail.replace("\x00", "").strip()
                    suffix = f": {detail}" if detail else ""
                    raise PowerShellExecutionError(
                        f"Windows probe {script_id.value} failed with exit code {completed.returncode}{suffix}"
                    )
        except subprocess.TimeoutExpired as exc:
            raise PowerShellExecutionError(
                f"Windows probe {script_id.value} timed out after {timeout_seconds:.1f}s"
            ) from exc
        except OSError as exc:
            raise PowerShellExecutionError(
                f"Unable to start configured PowerShell executable for {script_id.value}"
            ) from exc

        if not raw:
            raise PowerShellExecutionError(f"Windows probe {script_id.value} returned no JSON output")
        try:
            decoded = raw.decode("utf-8").strip()
            result = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PowerShellExecutionError(
                f"Windows probe {script_id.value} returned invalid UTF-8 JSON"
            ) from exc
        if not isinstance(result, dict):
            raise PowerShellExecutionError(
                f"Windows probe {script_id.value} must return a JSON object"
            )
        return result, len(raw)
