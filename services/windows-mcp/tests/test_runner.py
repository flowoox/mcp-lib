import base64
from types import SimpleNamespace

import pytest

from windows_mcp.config import WindowsTarget
from windows_mcp.runner import PowerShellExecutionError, PowerShellRunner
from windows_mcp.scripts import SCRIPTS, ScriptId


def test_executable_is_allowlisted_by_basename() -> None:
    PowerShellRunner(r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    with pytest.raises(ValueError, match="PowerShell"):
        PowerShellRunner("cmd.exe")


def test_static_scripts_do_not_contain_mutation_or_dynamic_evaluation_primitives() -> None:
    combined = "\n".join(SCRIPTS.values()).casefold()
    for forbidden in (
        "invoke-expression",
        "start-process",
        "set-service",
        "stop-service",
        "restart-service",
        "remove-item",
        "new-item",
        "set-itemproperty",
        "invoke-webrequest",
    ):
        assert forbidden not in combined


def test_remote_runner_keeps_target_and_payload_out_of_powershell_source(monkeypatch) -> None:
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed["env"] = kwargs["env"]
        observed["shell"] = kwargs["shell"]
        kwargs["stdout"].write(b'{"items":[],"nextCursor":null}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("windows_mcp.runner.subprocess.run", fake_run)
    runner = PowerShellRunner("powershell.exe")
    target = WindowsTarget(
        computer_name="server01.example.test",
        transport="winrm",
        configuration_name="FlowooxReadOnly",
    )
    result, size = runner.run(
        ScriptId.SERVICES,
        target,
        {"limit": 10, "offset": 0, "state": "running", "probeNonce": "caller-marker-123"},
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    source = base64.b64decode(observed["argv"][-1]).decode("utf-16le")
    assert "server01.example.test" not in source
    assert "caller-marker-123" not in source
    assert observed["env"]["FLOWOOX_MCP_TARGET"] == "server01.example.test"
    assert "caller-marker-123" in observed["env"]["FLOWOOX_MCP_INPUT"]
    assert observed["shell"] is False
    assert result == {"items": [], "nextCursor": None}
    assert size > 0


def test_runner_rejects_oversized_stdout_before_json_parse(monkeypatch) -> None:
    def fake_run(_argv, **kwargs):
        kwargs["stdout"].write(b"x" * 2048)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("windows_mcp.runner.subprocess.run", fake_run)
    runner = PowerShellRunner("powershell.exe")
    with pytest.raises(PowerShellExecutionError, match="response byte limit"):
        runner.run(
            ScriptId.HOST,
            WindowsTarget(computer_name=".", transport="local"),
            {},
            timeout_seconds=5,
            max_response_bytes=1024,
        )
