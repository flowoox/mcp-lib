from __future__ import annotations

import base64
import json
import subprocess

import pytest

from ad_mcp.runner import PowerShellExecutionError, PowerShellRunner
from ad_mcp.scripts import SCRIPTS, ScriptId


def test_runner_rejects_arbitrary_executable() -> None:
    with pytest.raises(ValueError):
        PowerShellRunner("cmd.exe")


def test_runner_uses_static_encoded_script_and_json_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout='{"enabled":true}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = PowerShellRunner("powershell.exe", timeout_seconds=12)
    identity = "alice'; Remove-ADUser -Confirm:$false; '"
    result = runner.run(ScriptId.GET_USER, {"identity": identity})

    args = captured["args"]
    assert isinstance(args, list)
    encoded = args[args.index("-EncodedCommand") + 1]
    decoded = base64.b64decode(encoded).decode("utf-16le")
    assert decoded == SCRIPTS[ScriptId.GET_USER]
    assert identity not in decoded
    assert captured["shell"] is False

    env = captured["env"]
    assert isinstance(env, dict)
    assert json.loads(env["FLOWOOX_MCP_INPUT"]) == {"identity": identity}
    assert result == {"enabled": True}


def test_runner_fails_closed_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="not-json", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(PowerShellExecutionError, match="invalid JSON"):
        PowerShellRunner("pwsh.exe").run(ScriptId.DOMAIN_SUMMARY)


def test_runner_normalizes_nonzero_exit_without_echoing_input(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr="ActiveDirectory module unavailable",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    secret_like_input = "do-not-reflect-this-value"
    with pytest.raises(PowerShellExecutionError) as exc_info:
        PowerShellRunner("powershell.exe").run(
            ScriptId.GET_USER, {"identity": secret_like_input}
        )
    assert secret_like_input not in str(exc_info.value)


def test_mutation_commands_are_confined_to_explicit_static_scripts() -> None:
    mutation_scripts = {
        ScriptId.SET_USER_ENABLED,
        ScriptId.SET_USER_GROUP_MEMBERSHIP,
    }
    forbidden_everywhere = (
        "Invoke-Expression",
        "Start-Process",
        "powershell -Command",
        "pwsh -Command",
        "New-ADUser",
        "Remove-ADUser",
        "Set-ADAccountPassword",
        "-Repair",
    )
    combined = "\n".join(SCRIPTS.values())
    assert not any(command.casefold() in combined.casefold() for command in forbidden_everywhere)

    mutation_tokens = (
        "Enable-ADAccount",
        "Disable-ADAccount",
        "Add-ADGroupMember",
        "Remove-ADGroupMember",
    )
    for script_id, source in SCRIPTS.items():
        has_mutation = any(token.casefold() in source.casefold() for token in mutation_tokens)
        assert has_mutation is (script_id in mutation_scripts)
