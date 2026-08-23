import pytest

from fortigate_mcp.config import Settings, normalize_base_url, parse_allowed_vdoms


def test_base_url_requires_bare_https_origin() -> None:
    assert normalize_base_url("https://fw.example.test:8443/") == "https://fw.example.test:8443"
    for value in (
        "http://fw.example.test",
        "https://user:pass@fw.example.test",
        "https://fw.example.test/api/v2",
        "https://fw.example.test?x=1",
    ):
        with pytest.raises(ValueError):
            normalize_base_url(value)


def test_vdom_allowlist_and_resolution_fail_closed() -> None:
    assert parse_allowed_vdoms("root;dmz") == frozenset({"root", "dmz"})
    settings = Settings(fortigate_allowed_vdoms="root;dmz", fortigate_default_vdom="root")
    assert settings.resolve_vdom(None) == "root"
    assert settings.resolve_vdom("dmz") == "dmz"
    with pytest.raises(PermissionError, match="outside"):
        settings.resolve_vdom("prod")


def test_insecure_tls_requires_explicit_override() -> None:
    settings = Settings(fortigate_tls_verify=False, fortigate_allow_insecure_tls=False)
    with pytest.raises(ValueError, match="ALLOW_INSECURE"):
        settings.tls_verify_value()
    assert Settings(
        fortigate_tls_verify=False,
        fortigate_allow_insecure_tls=True,
    ).tls_verify_value() is False
