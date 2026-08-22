from __future__ import annotations

import base64
import json
import subprocess

import pytest

from ad_mcp.provisioning_scripts import PROVISIONING_SCRIPTS, ProvisioningScriptId
from ad_mcp.runner import PowerShellExecutionError, PowerShellRunner
from ad_mcp.scripts import SCRIPTS, ScriptId


def test_runner_rejects_arbitrary_executable() -> None:
    with pytest.raises(ValueError):
        PowerShellRunner("cmd.exe")


def test_runner_uses_static_encoded_script_and_json_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout='{"enabled":true}', stderr=""
        )

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
    assert captured["input"] is None

    env = captured["env"]
    assert isinstance(env, dict)
    assert json.loads(env["FLOWOOX_MCP_INPUT"]) == {"identity": identity}
    assert result == {"enabled": True}


def test_runner_can_select_only_registered_provisioning_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout='{"changed":true}', stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = PowerShellRunner("powershell.exe").run(
        ProvisioningScriptId.CREATE_DISABLED_USER,
        {"samAccountName": "alice"},
    )
    args = captured["args"]
    assert isinstance(args, list)
    encoded = args[args.index("-EncodedCommand") + 1]
    decoded = base64.b64decode(encoded).decode("utf-16le")
    assert decoded == PROVISIONING_SCRIPTS[ProvisioningScriptId.CREATE_DISABLED_USER]
    assert result == {"changed": True}


def test_secret_runner_keeps_password_out_of_argv_source_and_json_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout='{"changed":true,"credentialEstablished":true}',
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    secret = "Correct-Horse-Battery-Staple-42!"
    payload = {
        "identity": "alice",
        "expectedObjectGuid": "11111111-2222-3333-4444-555555555555",
    }
    result = PowerShellRunner("powershell.exe").run_with_secret(
        ProvisioningScriptId.SET_INITIAL_PASSWORD,
        payload,
        secret=secret,
    )

    args = captured["args"]
    assert isinstance(args, list)
    assert all(secret not in str(item) for item in args)
    encoded = args[args.index("-EncodedCommand") + 1]
    decoded = base64.b64decode(encoded).decode("utf-16le")
    assert decoded == PROVISIONING_SCRIPTS[ProvisioningScriptId.SET_INITIAL_PASSWORD]
    assert secret not in decoded
    env = captured["env"]
    assert isinstance(env, dict)
    assert secret not in json.dumps(env)
    assert json.loads(env["FLOWOOX_MCP_INPUT"]) == payload
    assert captured["input"] == secret
    assert result["credentialEstablished"] is True


def test_runner_fails_closed_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout="not-json", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(PowerShellExecutionError, match="invalid JSON"):
        PowerShellRunner("pwsh.exe").run(ScriptId.DOMAIN_SUMMARY)


def test_runner_normalizes_nonzero_exit_without_echoing_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_secret_runner_redacts_secret_if_child_error_accidentally_contains_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "never-return-this-secret"

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr=f"provider error accidentally included {secret}",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(PowerShellExecutionError) as exc_info:
        PowerShellRunner("powershell.exe").run_with_secret(
            ProvisioningScriptId.SET_INITIAL_PASSWORD,
            {
                "identity": "alice",
                "expectedObjectGuid": "11111111-2222-3333-4444-555555555555",
            },
            secret=secret,
        )
    assert secret not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


def test_mutation_commands_are_confined_to_explicit_static_scripts() -> None:
    mutation_scripts = {
        ScriptId.SET_USER_ENABLED,
        ScriptId.SET_USER_GROUP_MEMBERSHIP,
    }
    provisioning_create_scripts = {ProvisioningScriptId.CREATE_DISABLED_USER}
    credential_mutation_scripts = {ProvisioningScriptId.SET_INITIAL_PASSWORD}
    all_sources = {**SCRIPTS, **PROVISIONING_SCRIPTS}

    forbidden_everywhere = (
        "Invoke-Expression",
        "Start-Process",
        "powershell -Command",
        "pwsh -Command",
        "Remove-ADUser",
        "-AccountPassword",
        "-Repair",
    )
    combined = "\n".join(all_sources.values())
    assert not any(command.casefold() in combined.casefold() for command in forbidden_everywhere)

    normal_mutation_tokens = (
        "Enable-ADAccount",
        "Disable-ADAccount",
        "Add-ADGroupMember",
        "Remove-ADGroupMember",
    )
    for script_id, source in SCRIPTS.items():
        has_mutation = any(
            token.casefold() in source.casefold() for token in normal_mutation_tokens
        )
        assert has_mutation is (script_id in mutation_scripts)

    for script_id, source in PROVISIONING_SCRIPTS.items():
        has_create = "New-ADUser".casefold() in source.casefold()
        has_password_reset = "Set-ADAccountPassword".casefold() in source.casefold()
        assert has_create is (script_id in provisioning_create_scripts)
        assert has_password_reset is (script_id in credential_mutation_scripts)
        if script_id not in credential_mutation_scripts:
            assert "ConvertTo-SecureString".casefold() not in source.casefold()


def test_credential_script_reads_secret_only_from_stdin() -> None:
    source = PROVISIONING_SCRIPTS[ProvisioningScriptId.SET_INITIAL_PASSWORD]
    assert "[Console]::In.ReadToEnd()" in source
    assert "$p.password".casefold() not in source.casefold()
    assert "$env:FLOWOOX_MCP_SECRET".casefold() not in source.casefold()
    assert "Set-ADAccountPassword" in source
