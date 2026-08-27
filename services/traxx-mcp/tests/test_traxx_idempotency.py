from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp_common.store import AtomicJsonStore

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig


class StubImportClient(TraxxClient):
    def __init__(self, tmp_path: Path):
        super().__init__(
            RuntimeConfig(base_url="https://traxx.test"),
            downloads_dir=tmp_path,
            import_ledger=AtomicJsonStore(tmp_path / "imports.json", default={}),
        )
        self.calls = 0

    async def _import_album_folder_once(self, folder: str | Path, **_: Any) -> dict[str, Any]:
        self.calls += 1
        return {
            "folder": str(folder),
            "album_id": 42,
            "imported_count": 1,
            "unresolved_count": 0,
        }

    async def inspect_album_import(
        self, album_id: int, *, expected_tracks: int = 1
    ) -> dict[str, Any]:
        return {
            "album_id": album_id,
            "exists": True,
            "tracks_count": expected_tracks,
            "expected_tracks": expected_tracks,
            "complete": True,
        }


@pytest.mark.asyncio
async def test_completed_import_is_returned_from_persistent_ledger(tmp_path: Path) -> None:
    first_client = StubImportClient(tmp_path)
    first = await first_client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-1:traxx",
    )
    assert first["idempotent"] is False
    assert first_client.calls == 1
    assert first_client.import_ledger is not None
    assert first_client.import_ledger.read()["release-1:traxx"]["status"] == "completed"

    restarted_client = StubImportClient(tmp_path)
    second = await restarted_client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-1:traxx",
    )
    assert second["idempotent"] is True
    assert restarted_client.calls == 0


@pytest.mark.asyncio
async def test_completed_import_is_repaired_when_tracks_disappeared(tmp_path: Path) -> None:
    first_client = StubImportClient(tmp_path)
    await first_client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-damaged:traxx",
    )

    class DamagedImportClient(StubImportClient):
        async def inspect_album_import(
            self, album_id: int, *, expected_tracks: int = 1
        ) -> dict[str, Any]:
            return {
                "album_id": album_id,
                "exists": True,
                "tracks_count": expected_tracks - 1,
                "expected_tracks": expected_tracks,
                "complete": False,
            }

    restarted = DamagedImportClient(tmp_path)
    result = await restarted.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-damaged:traxx",
    )
    assert result["idempotent"] is False
    assert restarted.calls == 1


@pytest.mark.asyncio
async def test_missing_album_is_reported_as_repairable_drift(tmp_path: Path) -> None:
    class MissingAlbumClient(TraxxClient):
        async def request(self, method: str, path: str, **kwargs: Any) -> Any:
            del method, path, kwargs
            raise TraxxError("Traxx GET /api/v1/albums/84 failed (404): not found")

    client = MissingAlbumClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )
    result = await client.inspect_album_import(84, expected_tracks=3)

    assert result == {
        "album_id": 84,
        "exists": False,
        "tracks_count": 0,
        "expected_tracks": 3,
        "complete": False,
    }


class ResourceClient(TraxxClient):
    def __init__(self, tmp_path: Path):
        super().__init__(RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path)
        self.created: list[dict[str, Any]] = []

    async def search_resource(
        self, resource: str, name: str, *, limit: int = 20
    ) -> list[dict[str, Any]]:
        del name, limit
        if resource == "albums":
            return [{"id": 5, "name": "Shared Name", "artists": [{"id": 99}]}]
        if resource == "tracks":
            return [{"id": 7, "name": "Track", "number": 1, "album": {"id": 42}}]
        return []

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        assert method == "POST"
        self.created.append({"path": path, "json": kwargs.get("json")})
        return {"id": 42}


@pytest.mark.asyncio
async def test_album_deduplication_requires_matching_artist(tmp_path: Path) -> None:
    client = ResourceClient(tmp_path)
    album_id = await client.ensure_album("Shared Name", artist_id=1)
    assert album_id == 42
    assert client.created[0]["path"] == "/api/v1/albums"


@pytest.mark.asyncio
async def test_album_without_release_date_omits_invalid_null(tmp_path: Path) -> None:
    client = ResourceClient(tmp_path)
    await client.ensure_album("Undated", artist_id=1, release_date="")
    assert "release_date" not in client.created[0]["json"]


@pytest.mark.asyncio
async def test_partial_release_dates_are_completed_for_traxx(tmp_path: Path) -> None:
    client = ResourceClient(tmp_path)
    await client.ensure_album("Month Known", artist_id=1, release_date="2024-07")
    assert client.created[0]["json"]["release_date"] == "2024-07-01"


@pytest.mark.asyncio
async def test_track_deduplication_uses_title_number_and_album(tmp_path: Path) -> None:
    client = ResourceClient(tmp_path)
    existing = await client._find_existing_track(name="Track", album_id=42, number=1)
    assert existing and existing["id"] == 7
    assert await client._find_existing_track(name="Track", album_id=41, number=1) is None


def test_imported_track_id_supports_create_and_existing_response_shapes() -> None:
    assert TraxxClient._imported_track_id({"track": {"id": 7}}) == 7
    assert TraxxClient._imported_track_id(
        {"track": {"status": "success", "track": {"id": 8}}}
    ) == 8
    assert TraxxClient._imported_track_id({"track": {"status": "success"}}) is None


@pytest.mark.asyncio
async def test_uploaded_local_cover_is_preferred_over_external_hotlink(tmp_path: Path) -> None:
    from traxx_mcp.tus import TusUploadResult

    class CoverClient(TraxxClient):
        async def upload_file(self, path: Path, *, upload_type: str = "track"):
            assert path.name == "cover.jpg"
            assert upload_type == "image"
            return TusUploadResult(
                upload_url="https://traxx.test/tus/cover",
                bytes_uploaded=4,
                file_entry_id="cover-entry",
            )

        async def discover_file_entry(self, upload):  # noqa: ANN001
            assert upload.file_entry_id == "cover-entry"
            return {"file_url": "https://traxx.test/files/cover.jpg"}

    client = CoverClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )
    cover = tmp_path / "cover.jpg"
    cover.write_bytes(b"jpeg")
    result = await client._cover_url_for_traxx(
        external_url="https://external.test/cover.jpg",
        local_cover=cover,
    )
    assert result == "https://traxx.test/files/cover.jpg"


class RetriablePartialImportClient(StubImportClient):
    async def _import_album_folder_once(
        self, folder: str | Path, **_: Any
    ) -> dict[str, Any]:
        self.calls += 1
        if self.calls == 1:
            return {
                "folder": str(folder),
                "album_id": 42,
                "imported_count": 1,
                "unresolved_count": 1,
            }
        return {
            "folder": str(folder),
            "album_id": 42,
            "imported_count": 2,
            "unresolved_count": 0,
        }


@pytest.mark.asyncio
async def test_partial_import_is_retryable_and_only_success_is_cached(
    tmp_path: Path,
) -> None:
    client = RetriablePartialImportClient(tmp_path)
    first = await client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-partial:traxx",
    )
    assert first["unresolved_count"] == 1
    assert client.import_ledger is not None
    assert client.import_ledger.read()["release-partial:traxx"]["status"] == (
        "needs_configuration"
    )

    second = await client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-partial:traxx",
    )
    assert second["unresolved_count"] == 0
    assert client.calls == 2

    restarted = RetriablePartialImportClient(tmp_path)
    third = await restarted.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        idempotency_key="release-partial:traxx",
    )
    assert third["idempotent"] is True
    assert restarted.calls == 0


@pytest.mark.asyncio
async def test_import_assigns_all_track_artists_to_traxx(tmp_path: Path) -> None:
    import wave

    from traxx_mcp.tus import TusUploadResult

    album = tmp_path / "library" / "Album Artist" / "Album"
    album.mkdir(parents=True)
    audio_path = album / "01 - Collaboration.wav"
    with wave.open(str(audio_path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)

    class MultiArtistClient(TraxxClient):
        def __init__(self) -> None:
            super().__init__(
                RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
            )
            self.artist_ids = {"Album Artist": 1, "Main Artist": 2, "Guest Artist": 3}
            self.track_payload: dict[str, Any] | None = None
            self.auto_match_album: bool | None = None

        async def ensure_artist(self, name: str, **_: Any) -> int:
            return self.artist_ids[name]

        async def ensure_album(self, name: str, **_: Any) -> int:
            assert name == "Album"
            return 10

        async def _find_existing_track(self, **_: Any):
            return None

        async def upload_file(self, path: Path, *, upload_type: str = "track"):
            del upload_type
            return TusUploadResult(
                upload_url=f"https://traxx.test/tus/{path.name}",
                bytes_uploaded=path.stat().st_size,
                file_entry_id="entry-1",
                file_url="https://traxx.test/files/track.wav",
            )

        async def discover_file_entry(self, upload):  # noqa: ANN001
            return {
                "file_entry_id": upload.file_entry_id,
                "file_url": upload.file_url,
            }

        async def extract_metadata(
            self, file_entry_id: str, *, auto_match_album: bool = True
        ):
            assert file_entry_id == "entry-1"
            self.auto_match_album = auto_match_album
            return {"metadata": {"title": "Collaboration", "number": 1}}

        async def create_track(self, payload: dict[str, Any]):
            self.track_payload = payload
            return {"id": 99, **payload}

    client = MultiArtistClient()
    result = await client.import_album_folder(
        "library/Album Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        artist="Album Artist",
        album="Album",
        track_hints=[
            {
                "title": "Collaboration",
                "number": 1,
                "artists": ["Main Artist", "Guest Artist"],
            }
        ],
    )
    assert result["unresolved_count"] == 0
    assert client.track_payload is not None
    assert client.track_payload["artists"] == [2, 3]
    assert client.auto_match_album is False


@pytest.mark.asyncio
async def test_fully_rejected_folder_never_creates_an_empty_album(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import wave

    album = tmp_path / "library" / "Artist" / "Wrong Album"
    album.mkdir(parents=True)
    audio_path = album / "01 - Wrong Track.wav"
    with wave.open(str(audio_path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)

    monkeypatch.setattr(
        "traxx_mcp.client.verify_assignment",
        lambda assigned, *_args, **_kwargs: {
            path: "The file belongs to another release" for path in assigned
        },
    )

    class NoEntityClient(TraxxClient):
        async def ensure_artist(self, *_args: Any, **_kwargs: Any) -> int:
            raise AssertionError("artist must not be created")

        async def ensure_album(self, *_args: Any, **_kwargs: Any) -> int:
            raise AssertionError("album must not be created")

    client = NoEntityClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )

    with pytest.raises(
        TraxxError,
        match="No verified audio files remain|catalogue tracks have a distinct matching",
    ):
        await client.import_album_folder(
            "library/Artist/Wrong Album",
            dry_run=False,
            rights_confirmed=True,
            rights_basis="owned-copy",
            artist="Artist",
            album="Wrong Album",
            track_hints=[{"title": "Expected", "number": 1}],
        )


@pytest.mark.asyncio
async def test_load_cover_uses_existing_local_file_before_remote_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    class UnexpectedHttpClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            nonlocal called
            del args, kwargs
            called = True

        async def __aenter__(self):  # noqa: ANN201
            return self

        async def __aexit__(self, *args: Any) -> None:
            del args

        async def get(self, url: str):  # noqa: ANN201
            raise AssertionError(f"Remote cover must not be requested: {url}")

    monkeypatch.setattr("traxx_mcp.client.httpx.AsyncClient", UnexpectedHttpClient)
    local = tmp_path / "cover.jpg"
    local.write_bytes(b"local-cover")
    client = TraxxClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )

    data, mime, path = await client._load_cover(
        tmp_path, "https://external.test/cover.jpg"
    )

    assert called is False
    assert data == b"local-cover"
    assert mime == "image/jpeg"
    assert path == local
