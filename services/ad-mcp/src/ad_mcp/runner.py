from __future__ import annotations

import base64
import json
import os
import subprocess
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from .provisioning_scripts import PROVISIONING_SCRIPTS, ProvisioningScriptId
from .scripts import SCRIPTS, ScriptId

_ALLOWED_EXECUTABLES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
_PASSTHROUGH_ENV = ("PATH", "SystemRoot", "WINDIR", "PSModulePath", "TEMP", "TMP")
_ALL_SCRIPTS: dict[StrEnum, str] = {**SCRIPTS, **PROVISIONING_SCRIPTS}
_SECRET_STDIN_SCRIPTS = {ProvisioningScriptId.SET_INITIAL_PASSWORD}
AdScriptId = ScriptId | ProvisioningScriptId


class PowerShellExecutionError(RuntimeError):
    """A static AD probe failed or returned an invalid response."""


class PowerShellRunner:
    """Execute only repository-owned PowerShell scripts with JSON input.

    Model/user input is never interpolated into PowerShell source. Normal
    structured input is passed through a dedicated environment variable and
    decoded inside the static script. Credential material uses a separate
    ``run_with_secret`` path that writes the secret only to the child process
    stdin; it is never placed in argv, PowerShell source or the JSON payload.
    The subprocess is always launched with ``shell=False``.
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

    def run(
        self, script_id: AdScriptId, payload: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        return self._run(script_id, payload, secret=None)

    def run_with_secret(
        self,
        script_id: AdScriptId,
        payload: Mapping[str, Any] | None = None,
        *,
        secret: str,
    ) -> dict[str, Any]:
        """Execute the one allowlisted credential script with secret text on stdin only."""

        if script_id not in _SECRET_STDIN_SCRIPTS:
            raise ValueError("script is not allowlisted to receive secret stdin")
        if not secret:
            raise ValueError("secret must not be empty")
        if "\x00" in secret:
            raise ValueError("secret must not contain NUL characters")
        return self._run(script_id, payload, secret=secret)

    def _run(
        self,
        script_id: AdScriptId,
        payload: Mapping[str, Any] | None,
        *,
        secret: str | None,
    ) -> dict[str, Any]:
        try:
            script = _ALL_SCRIPTS[script_id]
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
                input=secret,
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
            if secret:
                detail = detail.replace(secret, "[REDACTED]")
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
