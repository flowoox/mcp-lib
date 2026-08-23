import pytest

from windows_mcp.config import Settings


def test_default_target_is_local_and_event_logs_are_bounded() -> None:
    settings = Settings(windows_backend_read_only=True)
    assert settings.targets["local"].transport == "local"
    assert settings.allowed_event_logs == frozenset({"System", "Application"})


def test_remote_target_requires_dedicated_jea_endpoint_by_default() -> None:
    settings = Settings(
        windows_backend_read_only=True,
        windows_targets_json='{"dc01":{"computer_name":"dc01.example.test","transport":"winrm","configuration_name":"Microsoft.PowerShell"}}',
    )
    with pytest.raises(ValueError, match="constrained JEA"):
        _ = settings.targets


def test_remote_target_accepts_named_constrained_endpoint() -> None:
    settings = Settings(
        windows_backend_read_only=True,
        windows_targets_json='{"dc01":{"computer_name":"dc01.example.test","transport":"winrm","configuration_name":"FlowooxReadOnly"}}',
    )
    target = settings.targets["dc01"]
    assert target.computer_name == "dc01.example.test"
    assert target.configuration_name == "FlowooxReadOnly"


def test_event_log_allowlist_rejects_wildcards() -> None:
    settings = Settings(windows_backend_read_only=True, windows_allowed_event_logs="System,Microsoft-Windows-*")
    with pytest.raises(ValueError, match="unsafe"):
        _ = settings.allowed_event_logs
