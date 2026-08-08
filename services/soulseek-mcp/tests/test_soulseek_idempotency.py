from __future__ import annotations

from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient
from soulseek_mcp.config import RuntimeConfig
from soulseek_mcp.models import AlbumCandidate, RemoteFile


def candidate() -> AlbumCandidate:
    return AlbumCandidate(
        candidate_id="candidate-1",
        search_id="search-1",
        username="peer",
        folder="Artist/Album",
        artist="Artist",
        album="Album",
        files=[RemoteFile(filename="Artist/Album/01.flac", size=123, extension="flac")],
        audio_file_count=1,
        total_file_count=1,
    )


@pytest.mark.asyncio
async def test_queue_uses_deterministic_batch_and_reuses_existing_batch() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd"))
    batches: dict[str, dict[str, Any]] = {}
    post_count = 0

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        nonlocal post_count
        del params
        if method == "GET":
            batch_id = path.rsplit("/", 1)[-1]
            return batches.get(batch_id)
        assert method == "POST"
        post_count += 1
        assert isinstance(json, dict)
        batch_id = str(json["id"])
        batches[batch_id] = {"id": batch_id, "state": "Queued"}
        return batches[batch_id]

    client.request = request  # type: ignore[method-assign]
    first = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )
    second = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )

    assert first["batch_id"] == second["batch_id"]
    assert first["artifact_path"] == "library/Artist/Album"
    assert second["idempotent"] is True
    assert post_count == 1


@pytest.mark.asyncio
async def test_existing_operation_can_be_resolved_without_candidate_payload() -> None:
    client = SlskdClient(RuntimeConfig(base_url="http://slskd"))
    seen: list[str] = []

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        del json, params, allow_not_found
        assert method == "GET"
        seen.append(path)
        return {"state": "Queued"}

    client.request = request  # type: ignore[method-assign]
    result = await client.get_existing_operation_batch(
        candidate_id="expired-candidate",
        external_id="release-1",
        destination="library/Artist/Album",
    )

    assert result is not None
    assert result["idempotent"] is True
    assert result["artifact_path"] == "library/Artist/Album"
    assert result["batch_id"] in seen[0]
