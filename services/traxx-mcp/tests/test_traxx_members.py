"""Reading a whole instance's listeners, not only the connected account."""

from __future__ import annotations

from typing import Any

import pytest

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig


class Recording(TraxxClient):
    def __init__(self, responses: dict[str, Any]):
        super().__init__(
            RuntimeConfig(base_url="https://traxx.test", token="t"), downloads_dir=None
        )
        self.responses = responses
        self.asked: list[str] = []

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_error: bool = False,
    ) -> Any:
        self.asked.append(path)
        return self.responses.get(path, {"pagination": {"data": []}})


@pytest.mark.asyncio
async def test_members_come_back_with_the_address_that_links_them() -> None:
    client = Recording(
        {
            "/api/v1/users": {
                "pagination": {
                    "data": [
                        {"id": 1, "name": "florian", "email": "florian@wohnhaas.ch"},
                        {"id": 3, "name": "Kai", "email": "api@tekoda.cloud"},
                    ]
                }
            }
        }
    )
    members = await client.list_members()
    assert [item["email"] for item in members] == [
        "florian@wohnhaas.ch",
        "api@tekoda.cloud",
    ]


@pytest.mark.asyncio
async def test_another_members_likes_are_readable_with_the_service_token() -> None:
    client = Recording(
        {
            "/api/v1/users/1/liked-artists": {
                "pagination": {"data": [{"id": 9, "name": "Bibio"}]}
            },
            "/api/v1/users/1/liked-tracks": {
                "pagination": {
                    "data": [{"id": 4, "name": "Lovers Carvings",
                              "artists": [{"name": "Bibio"}, {"name": "Olivia"}]}]
                }
            },
        }
    )

    taste = await client.member_taste("1", pages=1)

    ranked = {item["name"]: item["weight"] for item in taste["artists"]}
    # A liked artist vouches for more of that artist than a single track does.
    assert ranked["Bibio"] == 6.0
    assert ranked["Olivia"] == 1.0
    assert "/api/v1/users/1/liked-albums" in client.asked


@pytest.mark.asyncio
async def test_a_user_id_has_to_look_like_one() -> None:
    client = Recording({})
    with pytest.raises(TraxxError):
        # It goes into the path, so it is checked rather than trusted.
        await client.list_liked("artists", user_id="1/../../admin")
