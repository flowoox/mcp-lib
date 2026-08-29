from __future__ import annotations

import asyncio
from typing import Any

import pytest

from soulseek_mcp.client import ReconnectCoordinator, SlskdClient, SlskdError
from soulseek_mcp.config import RuntimeConfig

LOGGED_IN = {
    "state": "Connected, LoggedIn",
    "username": "radar-user",
    "isConnected": True,
    "isLoggedIn": True,
}
DISCONNECTED = {
    "state": "Disconnected",
    "username": "radar-user",
    "isConnected": False,
    "isLoggedIn": False,
}


class FastReconnectClient(SlskdClient):
    def __init__(
        self,
        *,
        connected: bool,
        connect_succeeds: bool = True,
        reconnect: ReconnectCoordinator | None = None,
    ) -> None:
        super().__init__(
            RuntimeConfig(
                base_url="http://slskd:5030",
                api_key="secret-api-key-that-must-not-leak",
                reconnect_wait_seconds=1,
                reconnect_cooldown_seconds=60,
            ),
            reconnect=reconnect,
        )
        self.status = dict(LOGGED_IN if connected else DISCONNECTED)
        self.connect_succeeds = connect_succeeds
        self.connect_calls = 0
        self.post_calls = 0
        self.fail_first_post_with_disconnect = False
        self.fail_every_post = False

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        del kwargs
        if path == "/api/v0/searches" and method == "GET":
            return []
        if path == "/api/v0/shares":
            return {"local": [{"alias": "music", "files": 4, "directories": 1}]}
        if path == "/api/v0/server":
            return self.status
        if path == "/api/v0/searches" and method == "POST":
            self.post_calls += 1
            if self.fail_every_post or (
                self.fail_first_post_with_disconnect and self.post_calls == 1
            ):
                self.status = dict(DISCONNECTED)
                raise SlskdError("slskd POST failed (409)", status_code=409)
            return {"id": "search-1", "state": "InProgress"}
        if path == "/api/v0/searches/search-1":
            return {"id": "search-1", "state": "Completed", "responses": []}
        raise AssertionError((method, path))

    async def connect_soulseek(self, *, wait_seconds: int = 25) -> dict[str, Any]:
        del wait_seconds
        self.connect_calls += 1
        # Yield so concurrent callers genuinely contend on the coordinator.
        await asyncio.sleep(0)
        if self.connect_succeeds:
            self.status = dict(LOGGED_IN)
        return {
            "state": self.status["state"],
            "username": self.status["username"],
            "logged_in": self.status["isLoggedIn"],
            "connected": self.status["isConnected"],
            "triggered": True,
        }


@pytest.mark.asyncio
async def test_health_repairs_a_dropped_connection_once() -> None:
    client = FastReconnectClient(connected=False)

    result = await client.health()

    assert result["logged_in"] is True
    assert result["auto_reconnect_triggered"] is True
    assert client.connect_calls == 1


@pytest.mark.asyncio
async def test_failed_reconnect_is_cooled_down_without_leaking_secrets() -> None:
    client = FastReconnectClient(connected=False, connect_succeeds=False)

    with pytest.raises(SlskdError) as first:
        await client.ensure_connected()
    with pytest.raises(SlskdError, match="frühestens") as second:
        await client.ensure_connected()

    assert client.connect_calls == 1
    assert "secret-api-key-that-must-not-leak" not in str(first.value)
    assert "secret-api-key-that-must-not-leak" not in str(second.value)


@pytest.mark.asyncio
async def test_concurrent_preflights_share_one_reconnect() -> None:
    coordinator = ReconnectCoordinator()
    client = FastReconnectClient(connected=False, reconnect=coordinator)

    first, second = await asyncio.gather(
        client.ensure_connected(),
        client.ensure_connected(),
    )

    assert first["logged_in"] is True
    assert second["logged_in"] is True
    assert client.connect_calls == 1


@pytest.mark.asyncio
async def test_search_retries_one_409_after_confirmed_disconnect() -> None:
    client = FastReconnectClient(connected=True)
    client.fail_first_post_with_disconnect = True

    _, _, stats = await client.search_album(artist="Artist", album="Album")

    assert client.post_calls == 2
    assert client.connect_calls == 1
    assert stats["auto_reconnect_triggered"] is True


@pytest.mark.asyncio
async def test_search_does_not_reconnect_for_other_409_conflict() -> None:
    client = FastReconnectClient(connected=True)
    client.fail_every_post = True

    async def still_logged_in() -> dict[str, Any]:
        return {
            "state": LOGGED_IN["state"],
            "username": LOGGED_IN["username"],
            "logged_in": True,
            "connected": True,
        }

    client.server_status = still_logged_in  # type: ignore[method-assign]

    with pytest.raises(SlskdError) as failure:
        await client.search_album(artist="Artist", album="Album")

    assert failure.value.status_code == 409
    assert client.post_calls == 1
    assert client.connect_calls == 0


@pytest.mark.asyncio
async def test_search_never_reconnects_twice_in_one_call() -> None:
    client = FastReconnectClient(connected=False)
    client.fail_every_post = True

    with pytest.raises(SlskdError) as failure:
        await client.search_album(artist="Artist", album="Album")

    assert failure.value.status_code == 409
    assert client.post_calls == 1
    assert client.connect_calls == 1
