import pytest

from entra_mcp.config import Settings


def test_guid_configuration_is_canonicalized() -> None:
    settings = Settings(
        entra_tenant_id="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        entra_client_id="BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
        entra_client_secret="secret",
    )
    assert settings.entra_tenant_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert settings.entra_client_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_invalid_tenant_identifier_fails_closed() -> None:
    with pytest.raises(ValueError, match="GUID"):
        Settings(entra_tenant_id="common")


def test_cloud_endpoints_are_fixed() -> None:
    assert Settings(entra_cloud="global").graph_origin == "https://graph.microsoft.com"
    assert Settings(entra_cloud="usgov").graph_origin == "https://graph.microsoft.us"
    assert Settings(entra_cloud="dod").graph_origin == "https://dod-graph.microsoft.us"
    assert Settings(entra_cloud="china").graph_origin == "https://microsoftgraph.chinacloudapi.cn"
