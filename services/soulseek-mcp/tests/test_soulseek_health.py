from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient, SlskdError
from soulseek_mcp.config import RuntimeConfig


class StubClient(SlskdClient):
    def __init__(self, server: Any, *, after_connect: Any = None) -> None:
        super().__init__(
            RuntimeConfig(
                base_url="http://slskd:5030",
                api_key="k",
                auto_reconnect=False,
            )
        )
        self.server = server
        self.after_connect = after_connect
        self.calls: list[tuple[str, str]] = []

    shares: Any = None

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls.append((method, path))
        if path == "/api/v0/searches":
            return []
        if path == "/api/v0/shares":
            return self.shares
        if path == "/api/v0/server":
            if method == "PUT":
                if self.after_connect is not None:
                    self.server = self.after_connect
                return ""
            if isinstance(self.server, Exception):
                raise self.server
            return self.server
        raise AssertionError(path)


@pytest.mark.asyncio
async def test_health_reports_the_logged_in_state() -> None:
    client = StubClient(
        {"state": "Connected, LoggedIn", "username": "rootflo", "isLoggedIn": True}
    )

    client.shares = {"local": [{"alias": "music", "files": 1200, "directories": 40}]}

    result = await client.health()

    assert result["ok"] is True
    assert result["logged_in"] is True
    assert result["soulseek_username"] == "rootflo"
    assert result["shared_files"] == 1200
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_an_empty_share_is_warned_about_not_hidden() -> None:
    client = StubClient(
        {"state": "Connected, LoggedIn", "username": "rootflo", "isLoggedIn": True}
    )
    client.shares = {"local": [{"alias": "music", "files": 0, "directories": 0}]}

    result = await client.health()

    # Searching works, but peers do not answer someone sharing nothing — which
    # looks exactly like a broken connector.
    assert result["ok"] is True
    assert result["shared_files"] == 0
    assert "keine Dateien freigegeben" in result["warnings"][0]


@pytest.mark.asyncio
async def test_disconnected_is_a_failure_not_a_green_light() -> None:
    client = StubClient({"state": "Disconnected"})

    # Searching answers 409 in this state, so reporting the connector as
    # healthy sent the operator looking in the wrong place.
    with pytest.raises(SlskdError, match="nicht im Soulseek-Netz angemeldet"):
        await client.health()


@pytest.mark.asyncio
async def test_connected_but_not_logged_in_is_also_a_failure() -> None:
    client = StubClient({"state": "Connected", "isConnected": True, "isLoggedIn": False})

    with pytest.raises(SlskdError, match="Zustand: Connected"):
        await client.health()


@pytest.mark.asyncio
async def test_missing_server_state_is_reported_as_not_logged_in() -> None:
    client = StubClient(None)

    with pytest.raises(SlskdError, match="nicht im Soulseek-Netz angemeldet"):
        await client.health()


@pytest.mark.asyncio
async def test_connect_triggers_a_login_and_waits_for_it() -> None:
    # slskd sits in state "None" until something asks it to log in, which is
    # exactly what happens after credentials are written to its config file.
    client = StubClient(
        {"state": "None", "isLoggedIn": False},
        after_connect={"state": "Connected, LoggedIn", "username": "rootflo", "isLoggedIn": True},
    )

    result = await client.connect_soulseek(wait_seconds=5)

    assert result["logged_in"] is True
    assert result["triggered"] is True
    assert ("PUT", "/api/v0/server") in client.calls


@pytest.mark.asyncio
async def test_connect_is_a_no_op_when_already_logged_in() -> None:
    client = StubClient({"state": "Connected, LoggedIn", "isLoggedIn": True})

    result = await client.connect_soulseek()

    assert result["triggered"] is False
    assert ("PUT", "/api/v0/server") not in client.calls


@pytest.mark.asyncio
async def test_a_login_that_never_completes_is_explained() -> None:
    client = StubClient({"state": "None", "isLoggedIn": False})

    result = await client.connect_soulseek(wait_seconds=2)

    assert result["logged_in"] is False
    # A taken user name is the common cause and is not otherwise visible.
    assert "schon vergeben" in result["note"]
