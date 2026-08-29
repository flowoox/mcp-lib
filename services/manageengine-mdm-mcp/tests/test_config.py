from __future__ import annotations

import pytest

from manageengine_mdm_mcp.client import ManageEngineMdmReadOnlyTransport
from manageengine_mdm_mcp.config import Settings


def test_api_origin_rejects_credentials_path_and_insecure_http() -> None:
    with pytest.raises(ValueError, match="credentials"):
        Settings(mdm_api_base_url="https://user:secret@mdm.example.test")
    with pytest.raises(ValueError, match="without an API path"):
        Settings(mdm_api_base_url="https://mdm.example.test/api/v1")
    with pytest.raises(ValueError, match="plain HTTP"):
        Settings(mdm_api_base_url="http://mdm.example.test")


def test_customer_id_is_bounded_decimal() -> None:
    assert Settings(mdm_customer_id=" 12345 ").mdm_customer_id == "12345"
    with pytest.raises(ValueError, match="decimal digits"):
        Settings(mdm_customer_id="tenant-a")


def test_transport_fails_closed_without_read_only_attestation() -> None:
    settings = Settings(
        mdm_api_base_url="https://mdm.example.test",
        mdm_api_token="token",
        mdm_backend_read_only=False,
    )
    with pytest.raises(ValueError, match="MDM_BACKEND_READ_ONLY"):
        ManageEngineMdmReadOnlyTransport(settings)


def test_transport_requires_endpoint_and_token() -> None:
    with pytest.raises(ValueError, match="MDM_API_BASE_URL and MDM_API_TOKEN"):
        ManageEngineMdmReadOnlyTransport(Settings(mdm_backend_read_only=True))
