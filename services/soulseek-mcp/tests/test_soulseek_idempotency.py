from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient
from soulseek_mcp.config import RuntimeConfig
from soulseek_mcp.models import AlbumCandidate, RemoteFile
from soulseek_mcp.repository import BatchRepository


def candidate() -> AlbumCandidate:
    return AlbumCandidate(
        candidate_id="candidate-1",
        search_id="search-1",
        username="peer",
        folder="Artist/Album",
        artist="Artist",
        album="Album",
        files=[
            RemoteFile(filename="Music\\Artist\\Album\\01 Deep.flac", size=123, extension="flac")
        ],
        audio_file_count=1,
        total_file_count=1,
    )


def build(tmp_path: Path) -> SlskdClient:
    return SlskdClient(
        RuntimeConfig(base_url="http://slskd"),
        batches=BatchRepository(tmp_path / "batches.json"),
        downloads_dir=tmp_path / "downloads",
    )


@pytest.mark.asyncio
async def test_an_album_is_queued_per_user_as_a_list_of_files(tmp_path: Path) -> None:
    client = build(tmp_path)
    calls: list[tuple[str, str, Any]] = []

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        del params, allow_not_found
        calls.append((method, path, json))
        if method == "GET":
            return {"username": "peer", "directories": []}
        return {}

    client.request = request  # type: ignore[method-assign]
    result = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )

    method, path, payload = calls[0]
    # slskd has no batch route: posting to .../downloads/batches is read as a
    # user named "batches" and answers "User batches appears to be offline".
    assert (method, path) == ("POST", "/api/v0/transfers/downloads/peer")
    assert payload == [{"filename": "Music\\Artist\\Album\\01 Deep.flac", "size": 123}]
    assert result["artifact_path"] == "library/Artist/Album"
    assert result["idempotent"] is False


@pytest.mark.asyncio
async def test_queueing_the_same_album_twice_transfers_it_once(tmp_path: Path) -> None:
    client = build(tmp_path)
    posts = 0

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        nonlocal posts
        del path, json, params, allow_not_found
        if method == "POST":
            posts += 1
            return {}
        return {"username": "peer", "directories": []}

    client.request = request  # type: ignore[method-assign]
    first = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )
    second = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )

    assert first["batch_id"] == second["batch_id"]
    assert second["idempotent"] is True
    assert posts == 1


@pytest.mark.asyncio
async def test_an_album_nobody_queued_here_is_not_invented(tmp_path: Path) -> None:
    client = build(tmp_path)

    async def request(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("slskd must not be asked about an unknown batch")

    client.request = request  # type: ignore[method-assign]
    assert (
        await client.get_existing_operation_batch(
            candidate_id="never-queued", external_id="release-1"
        )
        is None
    )


@pytest.mark.asyncio
async def test_a_finished_album_is_moved_into_the_requested_folder(
    tmp_path: Path,
) -> None:
    client = build(tmp_path)
    # slskd writes downloads under the remote folder's own name, which is not
    # where the importer looks.
    landed = client.downloads_dir / "Album"
    landed.mkdir(parents=True)
    # Mixed case on purpose: the remote path is only translated, never
    # lowercased, or the file cannot be found again on a case-sensitive disk.
    (landed / "01 Deep.flac").write_bytes(b"fLaC")

    async def request(
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        del path, json, params, allow_not_found
        if method == "POST":
            return {}
        return {
            "username": "peer",
            "directories": [
                {
                    "directory": "Music\\Artist\\Album",
                    "files": [
                        {
                            "filename": "Music\\Artist\\Album\\01 Deep.flac",
                            "state": "Completed, Succeeded",
                            "size": 123,
                            "bytesTransferred": 123,
                        }
                    ],
                }
            ],
        }

    client.request = request  # type: ignore[method-assign]
    queued = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )
    status = await client.get_batch(queued["batch_id"])

    assert status["state"] == "completed"
    assert status["collected"]["moved"] == 1
    assert (client.downloads_dir / "library/Artist/Album/01 Deep.flac").is_file()
    assert not (landed / "01 Deep.flac").exists()

    # A second poll must not report a failure just because the sources moved.
    again = await client.get_batch(queued["batch_id"])
    assert again["collected"]["already_collected"] is True
