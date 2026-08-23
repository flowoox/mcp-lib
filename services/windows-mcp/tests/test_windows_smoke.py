import os

import pytest

from windows_mcp.config import WindowsTarget
from windows_mcp.models import HostObservation
from windows_mcp.runner import PowerShellRunner
from windows_mcp.scripts import ScriptId


@pytest.mark.windows_smoke
@pytest.mark.skipif(os.name != "nt", reason="requires Windows PowerShell")
def test_host_probe_executes_with_real_windows_powershell() -> None:
    result, size = PowerShellRunner("powershell.exe").run(
        ScriptId.HOST,
        WindowsTarget(computer_name=".", transport="local"),
        {},
        timeout_seconds=20,
        max_response_bytes=262_144,
    )
    assert size > 0
    assert result["nextCursor"] is None
    host = HostObservation.model_validate(result["items"][0])
    assert host.logicalProcessors >= 1
    assert host.totalMemoryBytes > 0
