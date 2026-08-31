from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from soulseek_mcp.client import SlskdClient, SlskdError, deterministic_batch_id
from soulseek_mcp.config import RuntimeConfig
from soulseek_mcp.models import AlbumCandidate, DownloadBatch, RemoteFile
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
    (tmp_path / "downloads").mkdir(parents=True, exist_ok=True)
    return SlskdClient(
        RuntimeConfig(
            base_url="http://slskd",
            minimum_free_space_gib=0,
            minimum_free_space_percent=0,
        ),
        batches=BatchRepository(tmp_path / "batches.json"),
        downloads_dir=tmp_path / "downloads",
    )


def test_rejected_album_folder_is_archived_inside_download_root(tmp_path: Path) -> None:
    client = build(tmp_path)
    source = tmp_path / "downloads" / "library" / "Artist" / "Album"
    source.mkdir(parents=True)
    (source / "01.flac").write_bytes(b"audio")

    result = client.archive_download_folder(str(source), "recommendation-1")

    archived = Path(result["archived_path"])
    assert result["archived"] is True
    assert archived.parent == (tmp_path / "downloads" / ".radar-retry-archive" / "recommendation-1")
    assert (archived / "01.flac").read_bytes() == b"audio"
    assert not source.exists()


def test_retry_archive_rejects_paths_outside_download_root(tmp_path: Path) -> None:
    client = build(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ValueError, match="escapes configured root"):
        client.archive_download_folder(str(outside), "recommendation-1")


def test_verified_library_album_can_be_cleaned(tmp_path: Path) -> None:
    client = build(tmp_path)
    source = tmp_path / "downloads" / "library" / "profile-1" / "Artist" / "Album"
    source.mkdir(parents=True)
    (source / "01.flac").write_bytes(b"audio")

    result = client.cleanup_download_folder(str(source))

    assert result["removed"] is True
    assert not source.exists()


@pytest.mark.parametrize(
    "relative",
    [
        "",
        "library",
        "library/Artist",
        "library/Artist/Album",
        "share/Artist/Album",
        ".radar-retry-archive/job/Album",
    ],
)
def test_cleanup_is_confined_to_a_library_album(tmp_path: Path, relative: str) -> None:
    client = build(tmp_path)
    root = tmp_path / "downloads"
    root.mkdir(parents=True, exist_ok=True)
    target = root / relative if relative else root
    if target != root:
        target.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="below library"):
        client.cleanup_download_folder(str(target))


def test_retry_archive_cleanup_removes_only_expired_attempts(tmp_path: Path) -> None:
    client = build(tmp_path)
    archive = tmp_path / "downloads" / ".radar-retry-archive" / "recommendation-1"
    old = archive / "Album-old"
    recent = archive / "Album-recent"
    old.mkdir(parents=True)
    recent.mkdir(parents=True)
    (old / "01.flac").write_bytes(b"old audio")
    (recent / "01.flac").write_bytes(b"new audio")
    old_time = 1_700_000_000
    os.utime(old / "01.flac", (old_time, old_time))
    os.utime(old, (old_time, old_time))

    result = client.cleanup_retry_archive(retention_hours=72, limit=100)

    assert result["removed"] == ["recommendation-1/Album-old"]
    assert result["freed_bytes"] == len(b"old audio")
    assert result["retained_recent"] == 1
    assert not old.exists()
    assert (recent / "01.flac").is_file()


@pytest.mark.asyncio
async def test_queue_refuses_to_consume_the_disk_reserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = build(tmp_path)
    client.config = client.config.model_copy(
        update={"minimum_free_space_gib": 1, "minimum_free_space_percent": 0}
    )
    monkeypatch.setattr(
        "soulseek_mcp.client.shutil.disk_usage",
        lambda _path: SimpleNamespace(total=10 * 1024**3, used=9 * 1024**3, free=1024**3),
    )

    with pytest.raises(SlskdError, match="Speicherreserve"):
        await client.queue_candidate(candidate())


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
async def test_cancelled_album_can_be_queued_again(tmp_path: Path) -> None:
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
        del json, params, allow_not_found
        if method == "POST":
            posts += 1
            return {}
        if method == "GET":
            return {
                "directories": [
                    {
                        "files": [
                            {
                                "id": "transfer-1",
                                "filename": "Music\\Artist\\Album\\01 Deep.flac",
                                "state": "InProgress",
                            }
                        ]
                    }
                ]
            }
        if method == "DELETE":
            return {}
        raise AssertionError((method, path))

    client.request = request  # type: ignore[method-assign]
    first = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )
    await client.cancel_batch(first["batch_id"], remove=True)

    cancelled = await client.get_batch(first["batch_id"])
    second = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )

    assert cancelled["state"] == "cancelled"
    assert second["idempotent"] is False
    assert posts == 2
    stored = client.batches.get(first["batch_id"])
    assert stored is not None
    assert stored.cancelled is False
    assert stored.retries == {}


@pytest.mark.asyncio
async def test_collected_album_with_missing_artifact_can_be_queued_again(
    tmp_path: Path,
) -> None:
    client = build(tmp_path)
    posts = 0
    stale = candidate()
    batch_id = deterministic_batch_id(stale.candidate_id, "release-1")
    client.batches.save(
        DownloadBatch(
            batch_id=batch_id,
            candidate_id=stale.candidate_id,
            username=stale.username,
            filenames=[item.filename for item in stale.files],
            destination="library/Artist/Album",
            external_id="release-1",
            collected=True,
        )
    )

    async def request(method: str, path: str, **kwargs: Any) -> Any:
        nonlocal posts
        del path, kwargs
        if method == "POST":
            posts += 1
        return {}

    client.request = request  # type: ignore[method-assign]
    result = await client.queue_candidate(
        stale, destination="library/Artist/Album", external_id="release-1"
    )

    assert result["idempotent"] is False
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


@pytest.mark.asyncio
async def test_one_dropped_file_is_asked_for_again(tmp_path: Path) -> None:
    client = build(tmp_path)
    posts: list[Any] = []
    state = "Completed, Errored"

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
            posts.append(json)
            return {}
        return {
            "username": "peer",
            "directories": [
                {
                    "files": [
                        {
                            "filename": "Music\\Artist\\Album\\01 Deep.flac",
                            "state": state,
                            "size": 123,
                        }
                    ]
                }
            ],
        }

    client.request = request  # type: ignore[method-assign]
    queued = await client.queue_candidate(
        candidate(), destination="library/Artist/Album", external_id="release-1"
    )

    # A peer that drops one file of an otherwise finished album is normal; the
    # album must not be written off over it.
    first = await client.get_batch(queued["batch_id"])
    assert first["state"] == "active"
    assert first["retried"] == ["01 Deep.flac"]
    assert posts[-1] == [{"filename": "Music\\Artist\\Album\\01 Deep.flac", "size": 123}]

    await client.get_batch(queued["batch_id"])
    # After the agreed number of attempts it really is a failure.
    final = await client.get_batch(queued["batch_id"])
    assert final["state"] == "failed"
    assert final["retried"] == []


@pytest.mark.asyncio
async def test_failed_sidecar_does_not_fail_complete_audio_batch(tmp_path: Path) -> None:
    from soulseek_mcp.models import RemoteFile

    client = build(tmp_path)
    posts: list[Any] = []
    collected: list[list[dict[str, Any]]] = []
    album = candidate().model_copy(
        update={
            "files": [
                RemoteFile(filename="Music\\Artist\\Album\\01 Deep.flac", size=123),
                RemoteFile(filename="Music\\Artist\\Album\\album.nfo", size=12),
            ],
            "audio_file_count": 1,
            "total_file_count": 2,
        }
    )

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
            posts.append(json)
            return {}
        return {
            "directories": [
                {
                    "files": [
                        {
                            "filename": "Music\\Artist\\Album\\01 Deep.flac",
                            "state": "Completed, Succeeded",
                            "size": 123,
                        },
                        {
                            "filename": "Music\\Artist\\Album\\album.nfo",
                            "state": "Completed, Errored",
                            "size": 12,
                        },
                    ]
                }
            ]
        }

    client.request = request  # type: ignore[method-assign]
    client.collect_batch = (  # type: ignore[method-assign]
        lambda _record, files: collected.append(files) or {"moved": len(files)}
    )
    queued = await client.queue_candidate(
        album, destination="library/Artist/Album", external_id="release-sidecar"
    )

    status = await client.get_batch(queued["batch_id"])

    assert status["state"] == "completed"
    assert status["audio_file_count"] == 1
    assert status["audio_files_seen"] == 1
    assert status["collected"]["moved"] == 1
    assert len(posts) == 1
    assert [item["filename"] for item in collected[0]] == ["Music\\Artist\\Album\\01 Deep.flac"]
