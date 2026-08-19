from __future__ import annotations

from pathlib import Path

import pytest

from traxx_mcp.config import RuntimeConfig, get_settings

SECRET = "persisted-service-token"


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from traxx_mcp.server import create_server

    monkeypatch.setenv("TRAXX_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("TRAXX_IMPORT_LEDGER_FILE", str(tmp_path / "imports.json"))
    monkeypatch.setenv("TRAXX_ACTORS_FILE", str(tmp_path / "actors.json"))
    monkeypatch.setenv("DOWNLOADS_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("TRAXX_URL", "https://traxx.test")
    monkeypatch.setenv("TRAXX_TOKEN", SECRET)
    get_settings.cache_clear()
    try:
        yield create_server()
    finally:
        get_settings.cache_clear()


def test_runtime_base_url_is_a_bare_http_origin() -> None:
    assert RuntimeConfig(base_url="https://traxx.test/").base_url == "https://traxx.test"
    with pytest.raises(ValueError):
        RuntimeConfig(base_url="ftp://traxx.test")
    with pytest.raises(ValueError):
        RuntimeConfig(base_url="https://user:pass@traxx.test")
    with pytest.raises(ValueError):
        RuntimeConfig(base_url="https://traxx.test/api")


async def test_configure_cannot_redirect_existing_credentials(server) -> None:
    with pytest.raises(Exception) as excinfo:
        await server.call_tool(
            "configure_traxx",
            {
                "base_url": "https://evil.example",
                "token": "",
                "verify_tls": True,
            },
        )
    message = str(excinfo.value)
    assert "TRAXX_ALLOWED_ORIGINS" in message
    assert SECRET not in message


async def test_configure_rejects_tls_verification_disable_by_default(server) -> None:
    with pytest.raises(Exception) as excinfo:
        await server.call_tool(
            "configure_traxx",
            {
                "base_url": "https://traxx.test",
                "token": "",
                "verify_tls": False,
            },
        )
    assert "TRAXX_ALLOW_INSECURE_TLS" in str(excinfo.value)
    assert SECRET not in str(excinfo.value)


def test_server_has_explicit_transport_security(server) -> None:
    security = server.settings.transport_security
    assert security is not None
    assert security.enable_dns_rebinding_protection is True
    assert "mcp-traxx:*" in security.allowed_hosts
    assert "localhost:*" in security.allowed_hosts
    assert "https://evil.example" not in security.allowed_origins
