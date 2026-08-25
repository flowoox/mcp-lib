import pytest

from prtg_mcp.client import PrtgReadOnlyTransport
from prtg_mcp.config import Settings


def test_https_origin_is_normalized() -> None:
    settings = Settings(
        prtg_base_url="https://prtg.example.test/",
        prtg_api_key="secret",
        prtg_backend_read_only=True,
    )
    assert settings.prtg_base_url == "https://prtg.example.test"
    assert settings.configured is True


def test_http_requires_explicit_deployment_override() -> None:
    with pytest.raises(ValueError, match="plain HTTP"):
        Settings(prtg_base_url="http://prtg.example.test", prtg_api_key="secret")

    settings = Settings(
        prtg_base_url="http://prtg.example.test",
        prtg_api_key="secret",
        prtg_allow_insecure_http=True,
    )
    assert settings.prtg_base_url == "http://prtg.example.test"


def test_origin_rejects_credentials_paths_queries_and_fragments() -> None:
    invalid = (
        "https://user:pass@prtg.example.test",
        "https://prtg.example.test/prtg",
        "https://prtg.example.test?token=secret",
        "https://prtg.example.test/#fragment",
    )
    for url in invalid:
        with pytest.raises(ValueError):
            Settings(prtg_base_url=url, prtg_api_key="secret")


def test_transport_requires_read_only_assertion_and_credentials() -> None:
    with pytest.raises(ValueError, match="READ_ONLY"):
        PrtgReadOnlyTransport(
            Settings(prtg_base_url="https://prtg.example.test", prtg_api_key="secret")
        )

    with pytest.raises(ValueError, match="BASE_URL"):
        PrtgReadOnlyTransport(Settings(prtg_backend_read_only=True))
