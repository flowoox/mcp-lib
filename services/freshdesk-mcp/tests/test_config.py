from __future__ import annotations

import pytest

from freshdesk_mcp.client import FreshdeskReadOnlyTransport
from freshdesk_mcp.config import Settings


def test_api_origin_rejects_credentials_path_and_insecure_http() -> None:
    with pytest.raises(ValueError, match="credentials"):
        Settings(freshdesk_api_base_url="https://user:secret@helpdesk.example.test")
    with pytest.raises(ValueError, match="without an API path"):
        Settings(freshdesk_api_base_url="https://helpdesk.example.test/api/v2")
    with pytest.raises(ValueError, match="plain HTTP"):
        Settings(freshdesk_api_base_url="http://helpdesk.example.test")


def test_api_origin_is_normalized() -> None:
    settings = Settings(freshdesk_api_base_url="https://helpdesk.example.test/")
    assert settings.freshdesk_api_base_url == "https://helpdesk.example.test"


def test_transport_fails_closed_without_read_only_attestation() -> None:
    settings = Settings(
        freshdesk_api_base_url="https://helpdesk.example.test",
        freshdesk_api_key="token",
        freshdesk_backend_read_only=False,
    )
    with pytest.raises(ValueError, match="FRESHDESK_BACKEND_READ_ONLY"):
        FreshdeskReadOnlyTransport(settings)


def test_transport_requires_endpoint_and_key() -> None:
    with pytest.raises(ValueError, match="FRESHDESK_API_BASE_URL and FRESHDESK_API_KEY"):
        FreshdeskReadOnlyTransport(Settings(freshdesk_backend_read_only=True))
