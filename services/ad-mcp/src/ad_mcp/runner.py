from __future__ import annotations

import base64
import json
import os
import subprocess
from collections.abc import Mapping
from typing import Any

from .scripts import SCRIPTS, ScriptId

_ALLOWED_EXECUTABLES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
_PASSTHROUGH_ENV = ("PATH", "SystemRoot", "WINDIR", "PSModulePath", "TEMP", "TMP")


class PowerShellExecutionError(RuntimeError):
    """A static AD probe failed or returned an invalid response."""


class PowerShellRunner:
    """Execute only repository-owned PowerShell scripts with JSON input.

    Model/user input is never interpolated into PowerShell source. It is passed
    through a dedicated environment variable and decoded inside the static
    script. The subprocess is always launched with ``shell=False``.
    """

    def __init__(self, executable: str, *, timeout_seconds: int = 30):
        executable = executable.strip()
        if not executable:
            raise ValueError("AD_POWERSHELL_EXECUTABLE must not be blank")
        basename = executable.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if basename not in _ALLOWED_EXECUTABLES:
            raise ValueError("AD_POWERSHELL_EXECUTABLE must resolve to PowerShell or pwsh")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def run(self, script_id: ScriptId, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        try:
            script = SCRIPTS[script_id]
        except KeyError as exc:
            raise ValueError(f"Unknown AD script id: {script_id}") from exc

        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        env = {name: os.environ[name] for name in _PASSTHROUGH_ENV if name in os.environ}
        env["FLOWOOX_MCP_INPUT"] = json.dumps(
            dict(payload or {}), ensure_ascii=False, separators=(",", ":")
        )

        try:
            completed = subprocess.run(
                [
                    self.executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    encoded,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PowerShellExecutionError(
                f"AD probe {script_id.value} timed out after {self.timeout_seconds}s"
            ) from exc
        except OSError as exc:
            raise PowerShellExecutionError(
                f"Unable to start configured PowerShell executable for {script_id.value}"
            ) from exc

        if completed.returncode != 0:
            detail = (completed.stderr or "").strip().replace("\x00", "")[-1200:]
            suffix = f": {detail}" if detail else ""
            raise PowerShellExecutionError(
                f"AD probe {script_id.value} failed with exit code {completed.returncode}{suffix}"
            )

        stdout = (completed.stdout or "").strip()
        if not stdout:
            raise PowerShellExecutionError(f"AD probe {script_id.value} returned no JSON output")
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise PowerShellExecutionError(
                f"AD probe {script_id.value} returned invalid JSON"
            ) from exc
        if not isinstance(result, dict):
            raise PowerShellExecutionError(
                f"AD probe {script_id.value} must return a JSON object"
            )
        return result
