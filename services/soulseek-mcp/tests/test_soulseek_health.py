from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient, SlskdError
from soulseek_mcp.config import RuntimeConfig


class StubClient(SlskdClient):
    def __init__(self, server: Any) -> None:
        super().__init__(RuntimeConfig(base_url="http://slskd:5030", api_key="k"))
        self.server = server

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        if path == "/api/v0/searches":
            return []
        if path == "/api/v0/server":
            if isinstance(self.server, Exception):
                raise self.server
            return self.server
        raise AssertionError(path)


@pytest.mark.asyncio
async def test_health_reports_the_logged_in_state() -> None:
    client = StubClient({"state": "Connected, LoggedIn", "username": "rootflo"})

    result = await client.health()

    assert result["ok"] is True
    assert result["logged_in"] is True
    assert result["soulseek_username"] == "rootflo"


@pytest.mark.asyncio
async def test_disconnected_is_a_failure_not_a_green_light() -> None:
    client = StubClient({"state": "Disconnected"})

    # Searching answers 409 in this state, so reporting the connector as
    # healthy sent the operator looking in the wrong place.
    with pytest.raises(SlskdError, match="nicht im Soulseek-Netz angemeldet"):
        await client.health()


@pytest.mark.asyncio
async def test_connecting_without_login_is_also_a_failure() -> None:
    client = StubClient({"state": "Connected"})

    with pytest.raises(SlskdError, match="Zustand: Connected"):
        await client.health()


@pytest.mark.asyncio
async def test_missing_server_state_points_at_the_missing_account() -> None:
    client = StubClient(None)

    with pytest.raises(SlskdError, match="kein Soulseek-Konto"):
        await client.health()
