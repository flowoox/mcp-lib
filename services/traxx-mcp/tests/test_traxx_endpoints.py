from typing import Any

import pytest

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig


class RecordingClient(TraxxClient):
    """Captures requests instead of performing them."""

    def __init__(self, config: RuntimeConfig, responses: dict[str, Any]):
        super().__init__(config, downloads_dir=None)
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.json_bodies: dict[str, Any] = {}

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_error: bool = False,
    ) -> Any:
        self.calls.append((method, path, params))
        self.json_bodies[path] = json
        result = self.responses[path]
        if isinstance(result, Exception):
            raise result
        return result


def config(**overrides: Any) -> RuntimeConfig:
    return RuntimeConfig(base_url="https://traxx.test", token="t", **overrides)


def test_proxy_headers_are_sent_but_cannot_replace_authorization() -> None:
    client = TraxxClient(
        config(extra_headers={"X-Radar-Auth": "shared", "authorization": "attacker"}),
        downloads_dir=None,
    )
    headers = client.headers
    assert headers["X-Radar-Auth"] == "shared"
    # The connector's own credential must survive a hostile extra header.
    assert headers["Authorization"] == "Bearer t"


@pytest.mark.asyncio
async def test_health_uses_a_route_the_api_actually_has() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/users/me/playlists": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": {"playlists": []},
            }
        },
    )
    result = await client.health()
    assert result["ok"] is True
    # /api/v1/tracks does not exist on this API; only reads by id do.
    assert client.calls[0][1] == "/api/v1/users/me/playlists"


@pytest.mark.asyncio
async def test_html_error_page_is_attributed_to_the_proxy() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/users/me/playlists": {
                "status": 401,
                "headers": {"content-type": "text/html; charset=UTF-8"},
                "body": {"text": "<!doctype html><title>401 | Not Authorized</title>"},
            }
        },
    )
    # The API answers JSON for Accept: application/json, so HTML means something
    # in front of it replied instead.
    with pytest.raises(TraxxError, match="proxy or WAF"):
        await client.health()


@pytest.mark.asyncio
async def test_json_401_is_attributed_to_the_token() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/users/me/playlists": {
                "status": 401,
                "headers": {"content-type": "application/json"},
                "body": {"message": "Unauthenticated."},
            }
        },
    )
    with pytest.raises(TraxxError, match="API token was refused"):
        await client.health()


@pytest.mark.asyncio
async def test_404_html_is_attributed_to_the_url_not_a_proxy() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/users/me/playlists": {
                "status": 404,
                "headers": {"content-type": "text/html; charset=UTF-8"},
                "body": {"text": "<!doctype html>doorway to the great nothing"},
            }
        },
    )
    # BeMusic serves its own HTML 404 for unknown routes, so blaming a proxy
    # here sends the operator after the wrong thing entirely.
    with pytest.raises(TraxxError) as excinfo:
        await client.health()
    message = str(excinfo.value)
    assert "404" in message
    assert "proxy" not in message.casefold()
    assert "/api/v1" in message


@pytest.mark.asyncio
async def test_artist_lookup_goes_through_search() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/search": {
                "artists": [
                    {"id": 7, "name": "Burial"},
                    {"id": 9, "name": "Burial & Four Tet"},
                ]
            }
        },
    )
    found = await client._find_exact_resource("artists", "Burial")
    assert found == 7
    assert client.calls[0][1] == "/api/v1/search"
    assert client.calls[0][2]["query"] == "Burial"


@pytest.mark.asyncio
async def test_search_returns_nothing_for_an_unknown_name() -> None:
    client = RecordingClient(config(), {"/api/v1/search": {"artists": []}})
    assert await client._find_exact_resource("artists", "Nobody") is None


@pytest.mark.asyncio
async def test_library_refresh_updates_local_channels_and_nested_containers() -> None:
    client = RecordingClient(
        config(),
        {
            "/api/v1/channel": {
                "pagination": {
                    "data": [
                        {
                            "id": 12,
                            "config": {
                                "contentType": "autoUpdate",
                                "autoUpdateProvider": "local",
                                "contentModel": "track",
                            },
                        },
                        {
                            "id": 13,
                            "config": {
                                "contentType": "autoUpdate",
                                "autoUpdateProvider": "spotify",
                                "contentModel": "track",
                            },
                        },
                        {
                            "id": 8,
                            "config": {
                                "contentType": "manual",
                                "contentModel": "channel",
                            },
                        },
                        {
                            "id": 23,
                            "config": {
                                "contentType": "listAll",
                                "contentModel": "album",
                            },
                        },
                    ]
                }
            },
            "/api/v1/channel/12/update-content": {},
            "/api/v1/channel/8/update-content": {},
        },
    )

    result = await client.refresh_library_channels()

    assert result["refreshed"] == [12, 8]
    assert result["errors"] == []
    assert client.json_bodies["/api/v1/channel/12/update-content"] == {}
    revision = client.json_bodies["/api/v1/channel/8/update-content"]
    assert revision["channelConfig"]["radarLibraryRevision"]
    assert "/api/v1/channel/13/update-content" not in client.json_bodies
    assert "/api/v1/channel/23/update-content" not in client.json_bodies
