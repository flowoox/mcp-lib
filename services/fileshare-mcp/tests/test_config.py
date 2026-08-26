import pytest

from fileshare_mcp.config import Settings


def test_roots_are_product_neutral_and_unique() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares\\\\Data","share_name":"Data"}]',
        fileshare_backend_read_only=True,
    )
    assert settings.roots[0].alias == "data"
    assert settings.roots[0].share_name == "Data"


def test_backend_attestation_requires_configured_root() -> None:
    with pytest.raises(ValueError, match="at least one configured root"):
        Settings(fileshare_backend_read_only=True)


def test_duplicate_aliases_fail_closed() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\A"},{"alias":"data","path":"D:\\\\B"}]'
    )
    with pytest.raises(ValueError, match="aliases must be unique"):
        _ = settings.roots
