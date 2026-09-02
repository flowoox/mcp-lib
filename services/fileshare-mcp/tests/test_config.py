import pytest

from fileshare_mcp.config import Settings


def test_roots_are_product_neutral_and_unique() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares\\\\Data","share_name":"Data"}]',
        fileshare_backend_read_only=True,
    )
    assert settings.roots[0].alias == "data"
    assert settings.roots[0].share_name == "Data"
    assert settings.roots[0].content_read is False


def test_backend_attestation_requires_configured_root() -> None:
    with pytest.raises(ValueError, match="at least one configured root"):
        Settings(fileshare_backend_read_only=True)


def test_duplicate_aliases_fail_closed() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\A"},{"alias":"data","path":"D:\\\\B"}]'
    )
    with pytest.raises(ValueError, match="aliases must be unique"):
        _ = settings.roots


def test_content_analysis_requires_read_only_backend_and_root_opt_in() -> None:
    with pytest.raises(ValueError, match="BACKEND_READ_ONLY"):
        Settings(
            fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares","content_read":true}]',
            fileshare_content_read_enabled=True,
        )

    with pytest.raises(ValueError, match="content_read=true"):
        Settings(
            fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares"}]',
            fileshare_backend_read_only=True,
            fileshare_content_read_enabled=True,
        )


def test_safe_text_extension_policy_is_normalized_and_rejects_wildcards() -> None:
    settings = Settings(
        fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares","content_read":true}]',
        fileshare_backend_read_only=True,
        fileshare_content_read_enabled=True,
        fileshare_safe_text_extensions=" .TXT, .log,.txt ",
    )
    assert settings.safe_text_extensions == (".txt", ".log")

    with pytest.raises(ValueError, match="invalid extension"):
        Settings(
            fileshare_roots_json='[{"alias":"data","path":"D:\\\\Shares","content_read":true}]',
            fileshare_backend_read_only=True,
            fileshare_content_read_enabled=True,
            fileshare_safe_text_extensions="*.txt",
        )
