import pytest

from hyperv_mcp.config import Settings


def test_targets_fail_closed_when_missing() -> None:
    settings = Settings(hyperv_backend_read_only=True)
    with pytest.raises(ValueError, match="non-empty object"):
        _ = settings.targets


def test_jea_required_by_default_and_unrestricted_endpoint_rejected() -> None:
    settings = Settings(
        hyperv_backend_read_only=True,
        hyperv_targets_json=(
            '{"hv01":{"computer_name":"hv01","transport":"winrm",'
            '"configuration_name":"Microsoft.PowerShell"}}'
        ),
    )
    with pytest.raises(ValueError, match="dedicated constrained JEA"):
        _ = settings.targets


def test_local_target_requires_explicit_jea_opt_out() -> None:
    settings = Settings(
        hyperv_backend_read_only=True,
        hyperv_targets_json='{"local":{"computer_name":".","transport":"local"}}',
    )
    with pytest.raises(ValueError, match="HYPERV_REQUIRE_JEA=true"):
        _ = settings.targets

    settings = Settings(
        hyperv_backend_read_only=True,
        hyperv_require_jea=False,
        hyperv_targets_json='{"local":{"computer_name":".","transport":"local"}}',
    )
    assert settings.targets["local"].transport == "local"
