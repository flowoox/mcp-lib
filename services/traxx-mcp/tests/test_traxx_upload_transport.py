"""What the live instance taught us about uploading, kept as tests.

Every assertion here comes from a measurement against a running Traxx: the
upload route hides behind a catch-all that answers OPTIONS for any path, the
only accepted upload types are the ones the instance publishes, and the bytes
alone do not make a FileEntry.
"""

from pathlib import Path
from typing import Any

import httpx
import pytest

from traxx_mcp.client import TraxxClient, select_resource_items
from traxx_mcp.config import RuntimeConfig
from traxx_mcp.tus import TusUploadResult


def config(**overrides: Any) -> RuntimeConfig:
    return RuntimeConfig(base_url="https://traxx.test", token="t", **overrides)


class RoutedClient(TraxxClient):
    """A client whose HTTP is served by a callable instead of the network."""

    def __init__(self, handler, **overrides: Any):
        super().__init__(config(**overrides), downloads_dir=None)
        self._handler = handler
        self.requests: list[tuple[str, str]] = []

    def _transport(self) -> httpx.MockTransport:
        def record(request: httpx.Request) -> httpx.Response:
            self.requests.append((request.method, request.url.path))
            return self._handler(request)

        return httpx.MockTransport(record)


def install_transport(client: RoutedClient, monkeypatch: pytest.MonkeyPatch) -> None:
    original = httpx.AsyncClient

    def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = client._transport()
        return original(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched)


SPA_CATCH_ALL = {"content-type": "text/html"}
TUS_HEADERS = {"Tus-Resumable": "1.0.0", "Tus-Version": "1.0.0"}


@pytest.mark.asyncio
async def test_tus_route_is_found_behind_the_catch_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/tus/upload":
            return httpx.Response(200, headers=TUS_HEADERS)
        # Every other path is the single-page app, which answers 200 to
        # anything and would look reachable to a status-code check.
        return httpx.Response(200, headers=SPA_CATCH_ALL)

    client = RoutedClient(handler, tus_endpoint="/api/v1/tus/")
    install_transport(client, monkeypatch)
    assert await client._resolve_tus_endpoint() == "/api/v1/tus/upload"


@pytest.mark.asyncio
async def test_audio_is_uploaded_as_media_and_becomes_a_file_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    track = tmp_path / "01 Wir.flac"
    track.write_bytes(b"fLaC" + b"\x00" * 32)
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "OPTIONS":
            return httpx.Response(
                200,
                headers=TUS_HEADERS if path == "/api/v1/tus/upload" else SPA_CATCH_ALL,
            )
        if request.method == "POST" and path == "/api/v1/tus/upload":
            seen["metadata"] = request.headers["Upload-Metadata"]
            return httpx.Response(
                201, headers={"Location": "https://traxx.test/api/v1/tus/upload/abc-1"}
            )
        if request.method == "PATCH":
            return httpx.Response(204, headers={"Upload-Offset": "36"})
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Upload-Offset": "36"})
        if request.method == "POST" and path == "/api/v1/tus/entries":
            seen["finalize"] = request.read().decode()
            return httpx.Response(
                200,
                json={
                    "fileEntry": {"id": 422, "url": "storage/media/abc-1.flac"},
                    "status": "success",
                },
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    client = RoutedClient(handler)
    install_transport(client, monkeypatch)
    result = await client.upload_file(track, upload_type="track")

    # "track" is not a type this API knows; audio has to go in as "media".
    assert "uploadType bWVkaWE=" in seen["metadata"]
    # Dropping any of these three makes the create step answer 500.
    for required in ("clientExtension", "clientMime", "clientSize"):
        assert f"{required} " in seen["metadata"]
    # And "filename" must stay out: the server would store the file under that
    # literal path, so the next album with an "01 Intro.flac" would collide.
    assert "filename" not in seen["metadata"]
    assert "abc-1" in seen["finalize"]
    assert result.file_entry_id == "422"
    assert result.file_url == "storage/media/abc-1.flac"


@pytest.mark.asyncio
async def test_discovery_keeps_the_url_the_finalize_step_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"no request expected, got {request.url.path}")

    client = RoutedClient(handler)
    install_transport(client, monkeypatch)
    upload = TusUploadResult(
        upload_url="https://traxx.test/api/v1/tus/upload/abc-1",
        bytes_uploaded=36,
        file_entry_id="422",
        file_url="storage/media/abc-1.flac",
    )
    discovery = await client.discover_file_entry(upload)
    assert discovery["file_url"] == "storage/media/abc-1.flac"
    assert discovery["probes"] == []


def test_search_answer_is_read_by_bucket_not_by_first_data_list() -> None:
    # The tracks bucket comes first and is empty; reading it for an album
    # lookup is what created the same album over and over.
    payload = {
        "query": "Hurra die Welt geht unter",
        "results": {
            "tracks": {"data": []},
            "artists": {"data": [{"id": 90, "name": "K.I.Z"}]},
            "albums": {"data": [{"id": 19, "name": "Hurra die Welt geht unter"}]},
        },
    }
    assert select_resource_items(payload, "albums") == [
        {"id": 19, "name": "Hurra die Welt geht unter"}
    ]
    assert select_resource_items(payload, "artists") == [{"id": 90, "name": "K.I.Z"}]
    assert select_resource_items(payload, "tracks") == []
