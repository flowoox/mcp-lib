from __future__ import annotations

import pytest
from pydantic import ValidationError

from veeam_mcp.config import Settings


def test_base_url_is_origin_and_api_version_is_pinned() -> None:
    settings = Settings(
        veeam_api_base_url="https://veeam.example/",
        veeam_username="svc",
        veeam_password="secret",
    )
    assert settings.veeam_api_base_url == "https://veeam.example"
    assert settings.veeam_api_version == "1.3-rev2"

    with pytest.raises(ValidationError):
        Settings(veeam_api_base_url="https://veeam.example/api/v1")
    with pytest.raises(ValidationError):
        Settings(veeam_api_base_url="https://veeam.example", veeam_api_version="1.3-rev1")


def test_credentials_query_and_plain_http_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(veeam_api_base_url="https://user:pass@veeam.example?x=1")
    with pytest.raises(ValidationError):
        Settings(veeam_api_base_url="http://veeam.example")


def test_configured_does_not_imply_read_only_attestation() -> None:
    settings = Settings(
        veeam_api_base_url="https://veeam.example",
        veeam_username="svc",
        veeam_password="secret",
    )
    assert settings.configured is True
    assert settings.read_only_attested is False


def test_only_backup_viewer_satisfies_read_only_attestation() -> None:
    viewer = Settings(veeam_backend_read_only=True, veeam_backend_role="Backup Viewer")
    admin = Settings(veeam_backend_read_only=True, veeam_backend_role="Backup Administrator")
    assert viewer.read_only_attested is True
    assert admin.read_only_attested is False
