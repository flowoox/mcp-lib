from __future__ import annotations

import pytest
from pydantic import ValidationError

from wazuh_mcp.config import Settings


def test_origins_are_normalized_and_credentials_stay_out_of_urls() -> None:
    settings = Settings(
        wazuh_server_api_base_url="https://manager.example:55000/",
        wazuh_server_username="svc",
        wazuh_server_password="secret",
        wazuh_indexer_api_base_url="https://indexer.example:9200/",
        wazuh_indexer_username="svc-indexer",
        wazuh_indexer_password="secret",
    )
    assert settings.wazuh_server_api_base_url == "https://manager.example:55000"
    assert settings.wazuh_indexer_api_base_url == "https://indexer.example:9200"
    assert settings.server_configured is True
    assert settings.indexer_configured is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("wazuh_server_api_base_url", "https://user:pass@manager.example:55000"),
        ("wazuh_server_api_base_url", "https://manager.example:55000/api"),
        ("wazuh_server_api_base_url", "https://manager.example:55000?token=secret"),
        ("wazuh_indexer_api_base_url", "https://indexer.example:9200/_search"),
        ("wazuh_indexer_api_base_url", "http://indexer.example:9200"),
    ],
)
def test_unsafe_backend_urls_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_read_only_attestations_are_explicit() -> None:
    settings = Settings(
        wazuh_server_backend_read_only=True,
        wazuh_server_backend_role="readonly",
        wazuh_indexer_backend_read_only=True,
        wazuh_indexer_backend_role="mcp_wazuh_observer",
    )
    assert settings.server_read_only_attested is True
    assert settings.indexer_read_only_attested is True

    assert Settings(
        wazuh_server_backend_read_only=True,
        wazuh_server_backend_role="administrator",
    ).server_read_only_attested is False
    assert Settings(
        wazuh_indexer_backend_read_only=True,
        wazuh_indexer_backend_role="",
    ).indexer_read_only_attested is False
