from __future__ import annotations

import pytest
from pydantic import ValidationError

from unifi_mcp.config import Settings


def test_base_url_requires_official_network_integration_prefix() -> None:
    settings = Settings(
        unifi_api_base_url="https://console.example/proxy/network/integration/",
        unifi_api_key="secret",
    )
    assert settings.unifi_api_base_url == "https://console.example/proxy/network/integration"

    with pytest.raises(ValidationError):
        Settings(unifi_api_base_url="https://console.example/api", unifi_api_key="secret")


def test_credentials_query_and_plain_http_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(
            unifi_api_base_url="https://user:pass@console.example/proxy/network/integration?x=1",
            unifi_api_key="secret",
        )
    with pytest.raises(ValidationError):
        Settings(
            unifi_api_base_url="http://console.example/proxy/network/integration",
            unifi_api_key="secret",
        )


def test_configured_does_not_imply_read_only_attestation() -> None:
    settings = Settings(
        unifi_api_base_url="https://console.example/proxy/network/integration",
        unifi_api_key="secret",
    )
    assert settings.configured is True
    assert settings.unifi_backend_read_only is False
