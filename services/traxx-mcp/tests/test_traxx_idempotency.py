from __future__ import annotations

import wave
from pathlib import Path
from typing import Any

import pytest
from mcp_common.store import AtomicJsonStore

from traxx_mcp.client import TraxxClient, TraxxError
from traxx_mcp.config import RuntimeConfig
from traxx_mcp.tus import TusUploadResult


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
        self,
        album_id: int,
        *,
        expected_tracks: int = 1,
        track_hints: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        del track_hints
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
            self,
            album_id: int,
            *,
            expected_tracks: int = 1,
            track_hints: list[dict[str, Any]] | None = None,
        ) -> dict[str, Any]:
            del track_hints
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


@pytest.mark.asyncio
async def test_album_checker_rejects_unrelated_remote_tracks(tmp_path: Path) -> None:
    class WrongTracksClient(TraxxClient):
        async def request(self, method: str, path: str, **kwargs: Any) -> Any:
            del method, path, kwargs
            return {
                "album": {
                    "id": 42,
                    "name": "mean2me",
                    "tracks_count": 2,
                    "tracks": [
                        {"id": 1, "name": "angelface", "duration": 228_000},
                        {"id": 2, "name": "Unrelated Edit", "duration": 173_000},
                    ],
                }
            }

    client = WrongTracksClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )
    result = await client.inspect_album_import(
        42,
        expected_tracks=2,
        track_hints=[
            {"title": "angelface", "duration_ms": 228_000},
            {"title": "mean2me", "duration_ms": 173_000},
        ],
    )

    assert result["tracks_count"] == 2
    assert result["catalog_verification"]["matched_tracks"] == 1
    assert result["identity_verified"] is False
    assert result["complete"] is False


@pytest.mark.asyncio
async def test_album_count_without_catalogue_titles_is_not_identity_verified(
    tmp_path: Path,
) -> None:
    class CountOnlyClient(TraxxClient):
        async def request(self, method: str, path: str, **kwargs: Any) -> Any:
            del method, path, kwargs
            return {"album": {"id": 42, "name": "Album", "tracks_count": 2}}

    client = CountOnlyClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )
    result = await client.inspect_album_import(42, expected_tracks=2, track_hints=[])

    assert result["complete"] is True
    assert result["identity_verified"] is False


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

        async def _find_exact_resource(self, resource: str, name: str) -> int | None:
            if resource == "artists" and name == "Album Artist":
                return self.artist_ids[name]
            return None

        async def _find_existing_album(
            self, name: str, *, artist_id: int
        ) -> int | None:
            assert name == "Album"
            assert artist_id == self.artist_ids["Album Artist"]
            return None

        async def _create_album(self, name: str, **_: Any) -> int:
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
async def test_existing_album_tracks_are_not_uploaded_again(tmp_path: Path) -> None:
    import wave

    album = tmp_path / "library" / "Artist" / "Album"
    album.mkdir(parents=True)
    audio_path = album / "01 - Existing.wav"
    with wave.open(str(audio_path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)

    class ExistingTrackClient(TraxxClient):
        async def _find_exact_resource(self, resource: str, name: str) -> int | None:
            assert resource == "artists"
            assert name == "Artist"
            return 1

        async def _find_existing_album(
            self, name: str, *, artist_id: int
        ) -> int | None:
            assert name == "Album"
            assert artist_id == 1
            return 10

        async def _find_existing_track(self, **_: Any) -> dict[str, Any]:
            return {"id": 99, "name": "Existing", "number": 1}

        async def upload_file(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("an existing track must not be uploaded again")

        async def inspect_album_import(
            self,
            album_id: int,
            *,
            expected_tracks: int = 1,
            track_hints: list[dict[str, Any]] | None = None,
        ) -> dict[str, Any]:
            del track_hints
            return {
                "album_id": album_id,
                "exists": True,
                "tracks_count": expected_tracks,
                "expected_tracks": expected_tracks,
                "complete": True,
            }

    client = ExistingTrackClient(
        RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
    )
    result = await client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        artist="Artist",
        album="Album",
        track_hints=[{"title": "Existing", "number": 1, "artist": "Artist"}],
    )

    assert result["complete"] is True
    assert result["unique_track_count"] == 1
    assert result["imported"][0]["existing"] is True


@pytest.mark.asyncio
async def test_new_empty_album_is_rolled_back_when_every_track_create_fails(
    tmp_path: Path,
) -> None:
    import wave

    from traxx_mcp.tus import TusUploadResult

    album = tmp_path / "library" / "Artist" / "Album"
    album.mkdir(parents=True)
    audio_path = album / "01 - Track.wav"
    with wave.open(str(audio_path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)

    class RejectedTrackClient(TraxxClient):
        def __init__(self) -> None:
            super().__init__(
                RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
            )
            self.deleted: list[str] = []

        async def _find_exact_resource(self, resource: str, name: str) -> int | None:
            del resource, name
            return 1

        async def _find_existing_album(
            self, name: str, *, artist_id: int
        ) -> int | None:
            del name, artist_id
            return None

        async def _find_existing_track(self, **_: Any) -> None:
            return None

        async def _create_album(self, name: str, **_: Any) -> int:
            assert name == "Album"
            return 10

        async def upload_file(
            self, path: Path, *, upload_type: str = "track"
        ) -> TusUploadResult:
            del upload_type
            return TusUploadResult(
                upload_url=f"https://traxx.test/tus/{path.name}",
                bytes_uploaded=path.stat().st_size,
                file_entry_id="entry-1",
                file_url="https://traxx.test/files/track.wav",
            )

        async def discover_file_entry(self, upload: TusUploadResult) -> dict[str, Any]:
            return {
                "file_entry_id": upload.file_entry_id,
                "file_url": upload.file_url,
            }

        async def extract_metadata(
            self, file_entry_id: str, *, auto_match_album: bool = True
        ) -> dict[str, Any]:
            del file_entry_id, auto_match_album
            return {"metadata": {"title": "Track", "number": 1}}

        async def create_track(self, payload: dict[str, Any]) -> Any:
            del payload
            raise TraxxError("track validation failed")

        async def inspect_album_import(
            self,
            album_id: int,
            *,
            expected_tracks: int = 1,
            track_hints: list[dict[str, Any]] | None = None,
        ) -> dict[str, Any]:
            del track_hints
            return {
                "album_id": album_id,
                "exists": True,
                "tracks_count": 0,
                "expected_tracks": expected_tracks,
                "complete": False,
            }

        async def request(self, method: str, path: str, **_: Any) -> Any:
            assert method == "DELETE"
            self.deleted.append(path)
            return {"status": 204, "body": None}

    client = RejectedTrackClient()
    with pytest.raises(TraxxError, match="empty album was rolled back"):
        await client.import_album_folder(
            "library/Artist/Album",
            dry_run=False,
            rights_confirmed=True,
            rights_basis="owned-copy",
            artist="Artist",
            album="Album",
            track_hints=[{"title": "Track", "number": 1, "artist": "Artist"}],
        )

    assert client.deleted == ["/api/v1/albums/10"]


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


def _make_staging_album(tmp_path: Path, titles: list[str]) -> Path:
    album = tmp_path / "library" / "Artist" / "Album"
    album.mkdir(parents=True)
    for number, title in enumerate(titles, start=1):
        audio_path = album / f"{number:02d} - {title}.wav"
        with wave.open(str(audio_path), "wb") as handle:
            handle.setnchannels(1)
            handle.setsampwidth(2)
            handle.setframerate(8000)
            handle.writeframes(b"\x00\x00" * 800)
    return album


def _staging_track_hints(titles: list[str]) -> list[dict[str, Any]]:
    return [
        {"title": title, "number": number, "artist": "Artist"}
        for number, title in enumerate(titles, start=1)
    ]


class StagingLifecycleClient(TraxxClient):
    """Small import harness that exposes every FileEntry lifecycle decision."""

    def __init__(self, tmp_path: Path, titles: list[str]) -> None:
        super().__init__(
            RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
        )
        self.titles = titles
        self.existing_artist = True
        self.artist_was_created = True
        self.existing_album = False
        self.entity_error_stage = ""
        self.entity_error: Exception = TraxxError("entity failed")
        self.fail_guest_artist = False
        self.missing_file_urls: set[str] = set()
        self.metadata_by_file_id: dict[str, dict[str, Any]] = {}
        self.create_behaviors: list[Any] = []
        self.create_payloads: list[dict[str, Any]] = []
        self.lookup_calls: list[tuple[str, int, int]] = []
        self.lookup_handler: Any = None
        self.deleted_batches: list[list[str]] = []
        self.deleted_albums: list[str] = []
        self.inspect_tracks_count = 0
        self.entity_started = False

    async def check_upload_sizes(self, _files: list[Path]) -> str:
        return ""

    async def _load_cover(
        self, album_root: Path, cover_url: str, *, persist: bool = True
    ) -> tuple[bytes | None, str, Path | None]:
        del cover_url, persist
        return None, "image/jpeg", album_root / "cover.jpg"

    async def _cover_url_for_traxx(
        self,
        *,
        external_url: str,
        local_cover: Path | None,
        staging_file_entry_ids: list[str] | None = None,
    ) -> str:
        del external_url, local_cover
        if staging_file_entry_ids is not None:
            staging_file_entry_ids.append("900")
        return "https://traxx.test/files/cover.jpg"

    async def upload_file(
        self, path: Path, *, upload_type: str = "track"
    ) -> TusUploadResult:
        assert upload_type == "track"
        number = int(path.name.split(" ", 1)[0])
        file_entry_id = str(100 + number)
        return TusUploadResult(
            upload_url=f"https://traxx.test/tus/{file_entry_id}",
            bytes_uploaded=path.stat().st_size,
            file_entry_id=file_entry_id,
            file_url=f"https://traxx.test/files/{file_entry_id}.wav",
        )

    async def discover_file_entry(self, upload: TusUploadResult) -> dict[str, Any]:
        return {
            "file_entry_id": upload.file_entry_id,
            "file_url": (
                None
                if str(upload.file_entry_id) in self.missing_file_urls
                else upload.file_url
            ),
        }

    async def extract_metadata(
        self, file_entry_id: str, *, auto_match_album: bool = True
    ) -> dict[str, Any]:
        assert auto_match_album is False
        number = int(file_entry_id) - 100
        metadata = self.metadata_by_file_id.get(
            file_entry_id,
            {
                "title": self.titles[number - 1],
                "number": number,
                "duration": 100,
            },
        )
        return {"metadata": metadata}

    async def _find_exact_resource(self, resource: str, name: str) -> int | None:
        assert resource == "artists"
        assert name == "Artist"
        return 1 if self.existing_artist else None

    async def _ensure_artist_with_state(
        self,
        name: str,
        *,
        image: str = "",
        genres: list[str] | None = None,
    ) -> tuple[int, bool]:
        del image, genres
        self.entity_started = True
        if name == "Guest":
            if self.fail_guest_artist:
                raise TraxxError("guest lookup failed", method="GET", path="/artists")
            return 2, False
        assert name == "Artist"
        if self.entity_error_stage == "artist":
            raise self.entity_error
        return 1, self.artist_was_created

    async def _find_existing_album(
        self, name: str, *, artist_id: int
    ) -> int | None:
        assert name == "Album"
        assert artist_id == 1
        return 10 if self.existing_album else None

    async def _create_album(self, name: str, **_: Any) -> int:
        assert name == "Album"
        self.entity_started = True
        if self.entity_error_stage == "album":
            raise self.entity_error
        return 10

    async def _find_existing_track(
        self, *, name: str, album_id: int, number: int
    ) -> dict[str, Any] | None:
        self.lookup_calls.append((name, album_id, number))
        if self.lookup_handler is None:
            return None
        return self.lookup_handler(name, album_id, number, len(self.lookup_calls))

    async def create_track(self, payload: dict[str, Any]) -> Any:
        self.create_payloads.append(payload)
        index = len(self.create_payloads) - 1
        behavior = (
            self.create_behaviors[index]
            if index < len(self.create_behaviors)
            else {"track": {"id": 500 + index}}
        )
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior

    async def inspect_album_import(
        self,
        album_id: int,
        *,
        expected_tracks: int = 1,
        track_hints: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        del track_hints
        return {
            "album_id": album_id,
            "exists": True,
            "tracks_count": self.inspect_tracks_count,
            "expected_tracks": expected_tracks,
            "complete": self.inspect_tracks_count >= expected_tracks,
        }

    async def _delete_staging_file_entries(self, entry_ids: list[str]) -> bool:
        deduplicated = list(dict.fromkeys(str(value) for value in entry_ids if value))
        if deduplicated:
            self.deleted_batches.append(deduplicated)
        return True

    async def request(self, method: str, path: str, **_: Any) -> Any:
        assert method == "DELETE"
        self.deleted_albums.append(path)
        return {"status": 204, "body": None}


async def _run_staging_import(
    client: StagingLifecycleClient,
    titles: list[str],
    *,
    track_hints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return await client.import_album_folder(
        "library/Artist/Album",
        dry_run=False,
        rights_confirmed=True,
        rights_basis="owned-copy",
        artist="Artist",
        album="Album",
        track_hints=track_hints or _staging_track_hints(titles),
    )


@pytest.mark.asyncio
async def test_multidisc_import_uses_unique_flat_catalog_numbers(
    tmp_path: Path,
) -> None:
    import wave

    album = tmp_path / "library" / "Artist" / "Album"
    for disc, title in ((1, "First"), (2, "Second")):
        disc_path = album / f"CD{disc}"
        disc_path.mkdir(parents=True)
        with wave.open(str(disc_path / f"01 - {title}.wav"), "wb") as handle:
            handle.setnchannels(1)
            handle.setsampwidth(2)
            handle.setframerate(8000)
            handle.writeframes(b"\x00\x00" * 800)

    class MultiDiscClient(StagingLifecycleClient):
        async def upload_file(
            self, path: Path, *, upload_type: str = "track"
        ) -> TusUploadResult:
            assert upload_type == "track"
            file_entry_id = "101" if path.parent.name == "CD1" else "102"
            return TusUploadResult(
                upload_url=f"https://traxx.test/tus/{file_entry_id}",
                bytes_uploaded=path.stat().st_size,
                file_entry_id=file_entry_id,
                file_url=f"https://traxx.test/files/{file_entry_id}.wav",
            )

    client = MultiDiscClient(tmp_path, ["First", "Second"])
    client.metadata_by_file_id = {
        "101": {"title": "First", "number": 1, "duration": 100},
        "102": {"title": "Second", "number": 1, "duration": 100},
    }
    client.inspect_tracks_count = 2

    await _run_staging_import(
        client,
        ["First", "Second"],
        track_hints=[
            {"title": "First", "number": 1, "disc_number": 1, "artist": "Artist"},
            {"title": "Second", "number": 1, "disc_number": 2, "artist": "Artist"},
        ],
    )

    assert [payload["number"] for payload in client.create_payloads] == [1, 2]
    assert [(name, number) for name, _album, number in client.lookup_calls] == [
        ("First", 1),
        ("Second", 2),
    ]


@pytest.mark.asyncio
async def test_staging_cleanup_1_preflight_removes_cover_and_every_audio(
    tmp_path: Path,
) -> None:
    titles = ["One", "Two"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.missing_file_urls.add("102")

    with pytest.raises(TraxxError, match="before Traxx creates the album"):
        await _run_staging_import(client, titles)

    assert client.deleted_batches == [["900", "101", "102"]]
    assert client.entity_started is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stage", "artist_created", "ambiguous", "keep_cover"),
    [
        ("artist", False, False, False),
        ("artist", False, True, True),
        ("album", False, False, False),
        ("album", False, True, True),
        ("album", True, False, True),
    ],
)
async def test_staging_cleanup_2_entity_failure_only_keeps_possibly_referenced_cover(
    tmp_path: Path,
    stage: str,
    artist_created: bool,
    ambiguous: bool,
    keep_cover: bool,
) -> None:
    titles = ["One", "Two"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.entity_error_stage = stage
    client.existing_artist = stage == "album" and not artist_created
    client.artist_was_created = artist_created
    client.entity_error = TraxxError(
        "entity mutation failed",
        status_code=None if ambiguous else 422,
        method="POST",
        path=f"/api/v1/{stage}s",
        mutation_ambiguous=ambiguous,
    )

    with pytest.raises(TraxxError, match="entity mutation failed"):
        await _run_staging_import(client, titles)

    deleted = {entry for batch in client.deleted_batches for entry in batch}
    assert {"101", "102"} <= deleted
    assert ("900" not in deleted) is keep_cover


@pytest.mark.asyncio
async def test_staging_cleanup_3_ambiguous_create_with_negative_readback_keeps_audio(
    tmp_path: Path,
) -> None:
    titles = ["One"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.create_behaviors = [
        TraxxError(
            "connection closed after send",
            method="POST",
            path="/api/v1/tracks",
            mutation_ambiguous=True,
        )
    ]
    client.inspect_tracks_count = 1

    result = await _run_staging_import(client, titles)

    deleted = {entry for batch in client.deleted_batches for entry in batch}
    assert "101" not in deleted
    assert result["unresolved_count"] == 1


@pytest.mark.asyncio
async def test_staging_cleanup_4_lost_response_readback_uses_exact_sent_identity(
    tmp_path: Path,
) -> None:
    titles = ["Local Title"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.metadata_by_file_id["101"] = {
        "title": "Server Title",
        "number": "7/12",
        "duration": 100,
    }
    client.create_behaviors = [
        TraxxError(
            "response lost",
            method="POST",
            path="/api/v1/tracks",
            mutation_ambiguous=True,
        )
    ]
    client.lookup_handler = lambda name, _album, number, _call: (
        {"id": 777, "name": name, "number": number}
        if (name, number) == ("Server Title", 7)
        else None
    )
    client.inspect_tracks_count = 1

    result = await _run_staging_import(client, titles)

    assert client.create_payloads[0]["name"] == "Server Title"
    assert client.create_payloads[0]["number"] == 7
    assert client.lookup_calls[-1] == ("Server Title", 10, 7)
    assert result["imported"][0]["track"]["id"] == 777
    assert all("101" not in batch for batch in client.deleted_batches)


@pytest.mark.asyncio
async def test_staging_cleanup_5_definite_422_deletes_only_rejected_track_audio(
    tmp_path: Path,
) -> None:
    titles = ["One", "Two"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.create_behaviors = [
        {"track": {"id": 501}},
        TraxxError(
            "validation rejected",
            status_code=422,
            method="POST",
            path="/api/v1/tracks",
        ),
    ]
    client.inspect_tracks_count = 1

    result = await _run_staging_import(client, titles)

    deleted = {entry for batch in client.deleted_batches for entry in batch}
    assert deleted == {"102"}
    assert result["unique_track_count"] == 1
    assert result["unresolved_count"] == 1


@pytest.mark.asyncio
async def test_staging_cleanup_6_failure_before_create_deletes_audio_even_if_track_appears(
    tmp_path: Path,
) -> None:
    titles = ["One"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.fail_guest_artist = True
    client.lookup_handler = lambda name, _album, number, _call: {
        "id": 601,
        "name": name,
        "number": number,
    }
    client.inspect_tracks_count = 1
    hints = [{"title": "One", "number": 1, "artists": ["Artist", "Guest"]}]

    result = await _run_staging_import(client, titles, track_hints=hints)

    assert client.create_payloads == []
    assert "101" in {entry for batch in client.deleted_batches for entry in batch}
    assert result["imported"][0]["track"]["id"] == 601


@pytest.mark.asyncio
async def test_staging_cleanup_7_size_refusal_removes_current_and_unattempted_audio(
    tmp_path: Path,
) -> None:
    titles = ["One", "Two", "Three"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.create_behaviors = [
        TraxxError(
            "file may not be greater than the configured maximum",
            status_code=422,
            method="POST",
            path="/api/v1/tracks",
        )
    ]
    client.inspect_tracks_count = 0

    with pytest.raises(TraxxError, match="empty album was rolled back"):
        await _run_staging_import(client, titles)

    deleted = {entry for batch in client.deleted_batches for entry in batch}
    assert {"101", "102", "103"} <= deleted
    assert len(client.create_payloads) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("artist_created", [False, True])
async def test_staging_cleanup_8_empty_album_rollback_protects_new_artist_cover(
    tmp_path: Path, artist_created: bool
) -> None:
    titles = ["One"]
    _make_staging_album(tmp_path, titles)
    client = StagingLifecycleClient(tmp_path, titles)
    client.existing_artist = not artist_created
    client.artist_was_created = artist_created
    client.create_behaviors = [
        TraxxError(
            "validation rejected",
            status_code=422,
            method="POST",
            path="/api/v1/tracks",
        )
    ]
    client.inspect_tracks_count = 0

    with pytest.raises(TraxxError, match="empty album was rolled back"):
        await _run_staging_import(client, titles)

    deleted = {entry for batch in client.deleted_batches for entry in batch}
    assert "101" in deleted
    assert ("900" not in deleted) is artist_created
    assert client.deleted_albums == ["/api/v1/albums/10"]


@pytest.mark.asyncio
async def test_staging_cleanup_9_delete_payload_is_numeric_deduplicated_and_permanent(
    tmp_path: Path,
) -> None:
    class DeletePayloadClient(TraxxClient):
        def __init__(self) -> None:
            super().__init__(
                RuntimeConfig(base_url="https://traxx.test"), downloads_dir=tmp_path
            )
            self.calls: list[tuple[str, str, dict[str, Any], bool]] = []

        async def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None = None,
            allow_error: bool = False,
            **_: Any,
        ) -> Any:
            self.calls.append((method, path, json or {}, allow_error))
            return {"status": 204, "body": None}

    client = DeletePayloadClient()

    removed = await client._delete_staging_file_entries(
        ["902", "101", "902", "not-an-id", "0", "-4"]
    )

    assert removed is True
    assert client.calls == [
        (
            "POST",
            "/api/v1/file-entries/delete",
            {"entryIds": [101, 902], "deleteForever": True},
            True,
        )
    ]
    assert TraxxError(
        "rejected", status_code=422, method="POST"
    ).definitively_rejected
    assert not TraxxError(
        "timeout", status_code=408, method="POST", mutation_ambiguous=True
    ).definitively_rejected
