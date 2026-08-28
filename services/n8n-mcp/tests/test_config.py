import pytest

from n8n_mcp.client import N8nReadOnlyTransport
from n8n_mcp.config import Settings


def test_api_base_url_is_normalized_and_may_include_deployment_prefix() -> None:
    settings = Settings(
        n8n_api_base_url="https://n8n.example.test/automation/api/v1/",
        n8n_api_key="secret",
        n8n_backend_read_only=True,
    )
    assert settings.n8n_api_base_url == "https://n8n.example.test/automation/api/v1"
    assert settings.configured is True


def test_api_base_url_must_end_in_public_api_v1() -> None:
    with pytest.raises(ValueError, match="/api/v1"):
        Settings(n8n_api_base_url="https://n8n.example.test", n8n_api_key="secret")


def test_http_requires_explicit_deployment_override() -> None:
    with pytest.raises(ValueError, match="plain HTTP"):
        Settings(n8n_api_base_url="http://n8n.example.test/api/v1", n8n_api_key="secret")

    settings = Settings(
        n8n_api_base_url="http://n8n.example.test/api/v1",
        n8n_api_key="secret",
        n8n_allow_insecure_http=True,
    )
    assert settings.n8n_api_base_url == "http://n8n.example.test/api/v1"


def test_api_base_url_rejects_credentials_queries_fragments_and_dot_segments() -> None:
    invalid = (
        "https://user:pass@n8n.example.test/api/v1",
        "https://n8n.example.test/api/v1?token=secret",
        "https://n8n.example.test/api/v1#fragment",
        "https://n8n.example.test/a/../api/v1",
    )
    for url in invalid:
        with pytest.raises(ValueError):
            Settings(n8n_api_base_url=url, n8n_api_key="secret")


def test_workflow_allowlist_is_normalized_and_bounded() -> None:
    settings = Settings(n8n_allowed_workflow_ids=" abc,def,abc ")
    assert settings.n8n_allowed_workflow_ids == "abc,def"
    assert settings.allowed_workflow_ids == frozenset({"abc", "def"})

    with pytest.raises(ValueError, match="workflow IDs"):
        Settings(n8n_allowed_workflow_ids="bad id")


def test_transport_requires_read_only_assertion_and_credentials() -> None:
    with pytest.raises(ValueError, match="READ_ONLY"):
        N8nReadOnlyTransport(
            Settings(n8n_api_base_url="https://n8n.example.test/api/v1", n8n_api_key="secret")
        )

    with pytest.raises(ValueError, match="BASE_URL"):
        N8nReadOnlyTransport(Settings(n8n_backend_read_only=True))
