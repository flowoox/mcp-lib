from __future__ import annotations

from pathlib import Path

import pytest

from traxx_mcp.config import ActorRegistry, UnknownActorError, get_settings

SECRET = "sekrit-actor-token-42"


def registry(tmp_path: Path) -> ActorRegistry:
    return ActorRegistry(tmp_path / "actors.json")


def test_actor_registry_roundtrip(tmp_path: Path) -> None:
    actors = registry(tmp_path)
    assert actors.list_ids() == []
    actors.set("user-7", SECRET)
    actors.set("user-3", "other-token")
    assert actors.list_ids() == ["user-3", "user-7"]
    assert actors.token_for("user-7") == SECRET
    assert actors.remove("user-7") is True
    assert actors.remove("user-7") is False
    assert actors.list_ids() == ["user-3"]


def test_unknown_actor_raises_without_leaking_tokens(tmp_path: Path) -> None:
    actors = registry(tmp_path)
    actors.set("known", SECRET)
    with pytest.raises(UnknownActorError) as excinfo:
        actors.token_for("ghost")
    message = str(excinfo.value)
    assert "ghost" in message
    assert SECRET not in message


def test_actor_id_validation(tmp_path: Path) -> None:
    actors = registry(tmp_path)
    with pytest.raises(ValueError):
        actors.set("", SECRET)
    with pytest.raises(ValueError):
        actors.set("x" * 200, SECRET)
    with pytest.raises(ValueError):
        actors.set("user-7", "   ")
    # A failed validation must not echo the token either.
    with pytest.raises(ValueError) as excinfo:
        actors.set("", SECRET)
    assert SECRET not in str(excinfo.value)


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from traxx_mcp.server import create_server

    monkeypatch.setenv("TRAXX_CONFIG_FILE", str(tmp_path / "config.json"))
    monkeypatch.setenv("TRAXX_IMPORT_LEDGER_FILE", str(tmp_path / "imports.json"))
    monkeypatch.setenv("TRAXX_ACTORS_FILE", str(tmp_path / "actors.json"))
    monkeypatch.setenv("DOWNLOADS_DIR", str(tmp_path / "downloads"))
    monkeypatch.setenv("TRAXX_URL", "https://traxx.test")
    get_settings.cache_clear()
    try:
        yield create_server()
    finally:
        get_settings.cache_clear()


async def test_actor_tools_never_return_the_token(server) -> None:
    configured = await server.call_tool(
        "configure_traxx_actor", {"actor_id": "user-7", "token": SECRET}
    )
    assert SECRET not in str(configured)
    assert "***" in str(configured)

    listed = await server.call_tool("list_traxx_actors", {})
    assert "user-7" in str(listed)
    assert SECRET not in str(listed)

    removed = await server.call_tool("remove_traxx_actor", {"actor_id": "user-7"})
    assert SECRET not in str(removed)

    listed_again = await server.call_tool("list_traxx_actors", {})
    assert "user-7" not in str(listed_again)


async def test_playlist_tool_with_unknown_actor_fails_before_any_request(server) -> None:
    await server.call_tool(
        "configure_traxx_actor", {"actor_id": "known", "token": SECRET}
    )
    with pytest.raises(Exception) as excinfo:
        await server.call_tool(
            "list_playlists", {"page": 1, "per_page": 5, "actor_id": "ghost"}
        )
    message = str(excinfo.value)
    assert "ghost" in message
    assert SECRET not in message
