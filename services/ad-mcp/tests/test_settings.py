import pytest
from pydantic import SecretStr, ValidationError

from mcp_ad.settings import Settings


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "ad_host": "dc.example.internal",
        "ad_bind_dn": "reader@example.internal",
        "ad_bind_password": SecretStr("not-a-real-secret"),
        "ad_base_dn": "DC=example,DC=internal",
    }
    values.update(overrides)
    return Settings(**values)


def test_ldaps_is_enabled_by_default() -> None:
    settings = make_settings()
    assert settings.ad_use_ssl is True
    assert settings.ad_start_tls is False
    assert settings.bind_password == "not-a-real-secret"


def test_plain_ldap_fails_closed() -> None:
    with pytest.raises(ValidationError, match="Plain LDAP is disabled"):
        make_settings(ad_use_ssl=False, ad_start_tls=False)


def test_isolated_development_can_explicitly_allow_plain_ldap() -> None:
    settings = make_settings(
        ad_use_ssl=False,
        ad_start_tls=False,
        ad_allow_insecure=True,
    )
    assert settings.ad_allow_insecure is True


def test_ldaps_and_starttls_cannot_both_be_enabled() -> None:
    with pytest.raises(ValidationError, match="not both"):
        make_settings(ad_use_ssl=True, ad_start_tls=True)


def test_configured_scopes_are_deduplicated() -> None:
    settings = make_settings(
        ad_allowed_base_dns=(
            "DC=example,DC=internal;OU=People,DC=example,DC=internal;"
            "DC=example,DC=internal"
        )
    )
    assert settings.allowed_base_dns == (
        "DC=example,DC=internal",
        "OU=People,DC=example,DC=internal",
    )
