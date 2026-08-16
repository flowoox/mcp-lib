from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mcp_common.store import AtomicJsonStore

from traxx_mcp.client import TraxxClient
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
        return {"folder": str(folder), "imported_count": 1, "unresolved_count": 0}


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
async def test_track_deduplication_uses_title_number_and_album(tmp_path: Path) -> None:
    client = ResourceClient(tmp_path)
    existing = await client._find_existing_track(name="Track", album_id=42, number=1)
    assert existing and existing["id"] == 7
    assert await client._find_existing_track(name="Track", album_id=41, number=1) is None


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
                "imported_count": 1,
                "unresolved_count": 1,
            }
        return {
            "folder": str(folder),
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

        async def extract_metadata(self, file_entry_id: str, **_: Any):
            assert file_entry_id == "entry-1"
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
