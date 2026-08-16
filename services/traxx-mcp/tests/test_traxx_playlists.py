from __future__ import annotations

from typing import Any

import pytest

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig


class PlaylistRecordingClient(TraxxClient):
    """Captures playlist requests, bodies included, instead of performing them."""

    def __init__(self, responses: dict[str, Any], **client_kwargs: Any):
        super().__init__(
            RuntimeConfig(base_url="https://traxx.test", token="service-token"),
            downloads_dir=None,
            **client_kwargs,
        )
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_error: bool = False,
    ) -> Any:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "json": json,
                "params": params,
                "allow_error": allow_error,
            }
        )
        result = self.responses[f"{method} {path}"]
        if isinstance(result, Exception):
            raise result
        return result


def test_actor_token_replaces_only_the_authorization_bearer() -> None:
    config = RuntimeConfig(
        base_url="https://traxx.test",
        token="service-token",
        extra_headers={"X-Radar-Auth": "shared"},
    )
    service = TraxxClient(config, downloads_dir=None)
    actor = TraxxClient(config, downloads_dir=None, actor_token="actor-token")
    assert service.headers["Authorization"] == "Bearer service-token"
    assert actor.headers["Authorization"] == "Bearer actor-token"
    # Everything besides the bearer comes from the shared configuration.
    assert actor.headers["X-Radar-Auth"] == "shared"
    assert actor.config.base_url == service.config.base_url


async def test_list_playlists_uses_the_users_me_route() -> None:
    client = PlaylistRecordingClient(
        {"GET /api/v1/users/me/playlists": {"data": [{"id": 5, "name": "Radar"}]}}
    )
    result = await client.list_playlists(page=2, per_page=10)
    assert result["data"][0]["id"] == 5
    call = client.calls[0]
    assert call["path"] == "/api/v1/users/me/playlists"
    assert call["params"] == {"page": 2, "perPage": 10}


async def test_get_playlist_returns_inline_tracks() -> None:
    client = PlaylistRecordingClient(
        {
            "GET /api/v1/playlists/5": {
                "playlist": {"id": 5, "name": "Radar"},
                "tracks": [{"id": 11}, {"id": 12}],
            }
        }
    )
    result = await client.get_playlist(5)
    assert [track["id"] for track in result["tracks"]] == [11, 12]
    # The subresource is only probed when the playlist payload has no tracks.
    assert len(client.calls) == 1


async def test_get_playlist_falls_back_to_the_tracks_subresource() -> None:
    client = PlaylistRecordingClient(
        {
            "GET /api/v1/playlists/5": {"playlist": {"id": 5, "name": "Radar"}},
            "GET /api/v1/playlists/5/tracks": {
                "status": 200,
                "headers": {},
                "body": {"data": [{"id": 21}]},
            },
        }
    )
    result = await client.get_playlist(5)
    assert [track["id"] for track in result["tracks"]] == [21]
    assert client.calls[1]["path"] == "/api/v1/playlists/5/tracks"
    assert client.calls[1]["allow_error"] is True


async def test_update_playlist_sends_only_the_supplied_fields() -> None:
    client = PlaylistRecordingClient({"PUT /api/v1/playlists/5": {"id": 5}})
    await client.update_playlist(playlist_id=5, name="Renamed")
    assert client.calls[0]["method"] == "PUT"
    assert client.calls[0]["json"] == {"name": "Renamed"}

    client.calls.clear()
    await client.update_playlist(playlist_id=5, description="d", public=False)
    assert client.calls[0]["json"] == {"description": "d", "public": False}


async def test_update_playlist_without_fields_is_rejected() -> None:
    client = PlaylistRecordingClient({})
    with pytest.raises(TraxxError, match="at least one"):
        await client.update_playlist(playlist_id=5)
    assert client.calls == []


async def test_remove_playlist_tracks_mirrors_the_add_route() -> None:
    client = PlaylistRecordingClient({"POST /api/v1/playlists/5/tracks/remove": {}})
    await client.remove_playlist_tracks(playlist_id=5, track_ids=[1, 2])
    call = client.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "/api/v1/playlists/5/tracks/remove"
    assert call["json"] == {"ids": [1, 2]}


async def test_replace_playlist_tracks_removes_then_adds() -> None:
    client = PlaylistRecordingClient(
        {
            "GET /api/v1/playlists/5": {
                "playlist": {"id": 5},
                "tracks": [{"id": 1}, {"id": 2}],
            },
            "POST /api/v1/playlists/5/tracks/remove": {},
            "POST /api/v1/playlists/5/tracks/add": {},
        }
    )
    result = await client.replace_playlist_tracks(playlist_id=5, track_ids=[7, 8])
    sequence = [(call["method"], call["path"]) for call in client.calls]
    assert sequence == [
        ("GET", "/api/v1/playlists/5"),
        ("POST", "/api/v1/playlists/5/tracks/remove"),
        ("POST", "/api/v1/playlists/5/tracks/add"),
    ]
    assert client.calls[1]["json"] == {"ids": [1, 2]}
    assert client.calls[2]["json"] == {"ids": [7, 8]}
    assert result["removed_track_ids"] == [1, 2]
    assert result["added_track_ids"] == [7, 8]


async def test_replace_playlist_tracks_on_an_empty_playlist_only_adds() -> None:
    client = PlaylistRecordingClient(
        {
            "GET /api/v1/playlists/5": {"playlist": {"id": 5}},
            "GET /api/v1/playlists/5/tracks": {
                "status": 200,
                "headers": {},
                "body": {"data": []},
            },
            "POST /api/v1/playlists/5/tracks/add": {},
        }
    )
    result = await client.replace_playlist_tracks(playlist_id=5, track_ids=[7])
    methods = [(call["method"], call["path"]) for call in client.calls]
    assert ("POST", "/api/v1/playlists/5/tracks/remove") not in methods
    assert methods[-1] == ("POST", "/api/v1/playlists/5/tracks/add")
    assert result["removed_track_ids"] == []


async def test_replace_playlist_tracks_with_nothing_is_a_no_op() -> None:
    client = PlaylistRecordingClient(
        {
            "GET /api/v1/playlists/5": {"playlist": {"id": 5}},
            "GET /api/v1/playlists/5/tracks": {
                "status": 200,
                "headers": {},
                "body": {"data": []},
            },
        }
    )
    result = await client.replace_playlist_tracks(playlist_id=5, track_ids=[])
    # Idempotent: no remove, no add — reading the current state is all that ran.
    assert all(call["method"] == "GET" for call in client.calls)
    assert result == {
        "playlist_id": 5,
        "removed_track_ids": [],
        "added_track_ids": [],
    }
