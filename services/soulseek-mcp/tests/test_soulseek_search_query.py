from __future__ import annotations

from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient
from soulseek_mcp.config import RuntimeConfig


async def run_search(client: SlskdClient, **kwargs: Any) -> dict[str, Any]:
    """Capture the payload slskd would receive and answer with an empty search."""
    sent: dict[str, Any] = {}

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        del path, params, allow_not_found
        if method == "POST":
            sent.update(json or {})
            return {"id": "search-1", "state": "InProgress"}
        return {"id": "search-1", "state": "Completed", "responses": []}

    client.request = request  # type: ignore[method-assign]
    await client.search_album(artist="Artist", album="Album", **kwargs)
    return sent


@pytest.mark.asyncio
async def test_default_query_joins_artist_and_album() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd"))

    sent = await run_search(client)

    assert sent["searchText"] == "Artist Album"


@pytest.mark.asyncio
async def test_search_text_overrides_the_default_query() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd"))

    sent = await run_search(client, search_text="Artist")

    # Peers match every term against the file path, so a niche release often
    # answers only to the artist. Ranking still runs against artist and album.
    assert sent["searchText"] == "Artist"


@pytest.mark.asyncio
async def test_single_track_release_does_not_demand_four_files() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd", minimum_tracks=4))

    sent = await run_search(client, expected_track_count=1)

    # Taking the maximum of the two dropped every answer to a single before it
    # could be ranked: slskd filters responses below this count server-side.
    assert sent["minimumResponseFileCount"] == 1


@pytest.mark.asyncio
async def test_unknown_track_count_falls_back_to_the_configured_minimum() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd", minimum_tracks=4))

    sent = await run_search(client)

    assert sent["minimumResponseFileCount"] == 4


@pytest.mark.asyncio
async def test_search_timeout_reaches_slskd_in_milliseconds() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd", search_timeout=20))

    sent = await run_search(client)

    # slskd reads this field as milliseconds. Passing the seconds value ended
    # every search after 20 ms with zero responses, which made the whole
    # Soulseek network look unreachable.
    assert sent["searchTimeout"] == 20_000
