import pytest

from fileshare_mcp.backend import PowerShellFileShareBackend
from fileshare_mcp.config import Settings


def test_backend_requires_explicit_read_only_attestation() -> None:
    with pytest.raises(RuntimeError, match="READ_ONLY"):
        PowerShellFileShareBackend(Settings())


@pytest.mark.asyncio
async def test_backend_rejects_non_allowlisted_operation_before_platform_check() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares"}]',
        fileshare_backend_read_only=True,
    )
    backend = PowerShellFileShareBackend(settings)
    with pytest.raises(ValueError, match="allowlisted"):
        await backend.execute("write_file", timeout_seconds=1.0)


@pytest.mark.asyncio
async def test_backend_rejects_content_operation_when_feature_is_disabled() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares"}]',
        fileshare_backend_read_only=True,
    )
    backend = PowerShellFileShareBackend(settings)
    with pytest.raises(RuntimeError, match="CONTENT_READ_ENABLED"):
        await backend.execute(
            "text_preview",
            path=r"D:\Shares\report.txt",
            max_bytes=1024,
            max_chars=1024,
            max_lines=10,
            timeout_seconds=1.0,
        )
