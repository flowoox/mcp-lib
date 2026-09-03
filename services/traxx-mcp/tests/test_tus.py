from __future__ import annotations

import httpx
import pytest

from traxx_mcp.tus import TusError, TusUploader


def test_extracts_file_entry_from_headers():
    file_id, file_url = TusUploader.extract_identity(
        {"X-File-Entry-Id": "42", "X-File-Url": "/storage/a.mp3"},
        "https://x/api/tus/abc",
        None,
    )
    assert file_id == "42"
    assert file_url == "/storage/a.mp3"


def test_extracts_numeric_id_from_location():
    file_id, _ = TusUploader.extract_identity({}, "https://x/api/tus/123", None)
    assert file_id == "123"


def test_relative_upload_location_stays_on_internal_origin():
    result = TusUploader.resolve_upload_url(
        "http://bemusic-web:8080/api/v1/tus/upload",
        "http://bemusic-web:8080/api/v1/tus/upload",
        "/api/v1/tus/upload/abc-1",
        {"Host": "traxx.tekoda.cloud"},
    )

    assert result == "http://bemusic-web:8080/api/v1/tus/upload/abc-1"


def test_forwarded_public_upload_location_uses_internal_origin():
    result = TusUploader.resolve_upload_url(
        "http://bemusic-web:8080/api/v1/tus/upload",
        "http://bemusic-web:8080/api/v1/tus/upload",
        "https://traxx.tekoda.cloud/api/v1/tus/upload/abc-1?upload=track",
        {"Host": "traxx.tekoda.cloud"},
    )

    assert result == (
        "http://bemusic-web:8080/api/v1/tus/upload/abc-1?upload=track"
    )


def test_same_origin_absolute_upload_location_is_allowed():
    result = TusUploader.resolve_upload_url(
        "https://traxx.example/api/v1/tus/upload",
        "https://traxx.example/api/v1/tus/upload",
        "https://traxx.example/api/v1/tus/upload/abc-1?upload=track",
        {},
    )

    assert result == "https://traxx.example/api/v1/tus/upload/abc-1?upload=track"


def test_external_upload_location_is_rejected():
    with pytest.raises(TusError, match="cross-origin upload blocked"):
        TusUploader.resolve_upload_url(
            "http://bemusic-web:8080/api/v1/tus/upload",
            "http://bemusic-web:8080/api/v1/tus/upload",
            "https://uploads.example.net/tus/abc-1",
            {"Host": "traxx.tekoda.cloud"},
        )


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/tus/abc-1",
        "http://10.0.0.1/tus/abc-1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/tus/abc-1",
        "http://[fe80::1]/tus/abc-1",
        "http://[fd00::1]/tus/abc-1",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
    ],
)
def test_private_link_local_and_metadata_locations_are_rejected(target: str):
    with pytest.raises(TusError, match="cross-origin upload blocked"):
        TusUploader.resolve_upload_url(
            "https://traxx.example/api/v1/tus/upload",
            "https://traxx.example/api/v1/tus/upload",
            target,
            {},
        )


def test_scheme_downgrade_is_rejected():
    with pytest.raises(TusError, match="cross-origin upload blocked"):
        TusUploader.resolve_upload_url(
            "https://traxx.example/api/v1/tus/upload",
            "https://traxx.example/api/v1/tus/upload",
            "http://traxx.example/api/v1/tus/upload/abc-1",
            {},
        )


def test_location_userinfo_is_rejected():
    with pytest.raises(TusError, match="userinfo"):
        TusUploader.resolve_upload_url(
            "https://traxx.example/api/v1/tus/upload",
            "https://traxx.example/api/v1/tus/upload",
            "https://user:password@traxx.example/api/v1/tus/upload/abc-1",
            {},
        )


@pytest.mark.asyncio
async def test_tus_create_redirect_is_not_followed(tmp_path):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://attacker.example/tus/abc-1"},
            request=request,
        )

    path = tmp_path / "track.flac"
    path.write_bytes(b"audio")
    uploader = TusUploader(
        endpoint="https://traxx.example/api/v1/tus/upload",
        headers={
            "Authorization": "Bearer service-secret",
            "X-Radar-Auth": "proxy-secret",
        },
        verify_tls=True,
        chunk_size=256 * 1024,
        timeout=30,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(TusError, match="redirect blocked"):
        await uploader.upload(path)

    assert [request.url.host for request in requests] == ["traxx.example"]


@pytest.mark.asyncio
async def test_cross_origin_tus_location_is_blocked_before_patch_or_secret_forward(tmp_path):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            201,
            headers={"Location": "https://attacker.example/tus/abc-1"},
            request=request,
        )

    path = tmp_path / "track.flac"
    path.write_bytes(b"audio")
    uploader = TusUploader(
        endpoint="https://traxx.example/api/v1/tus/upload",
        headers={
            "Authorization": "Bearer service-secret",
            "X-Radar-Auth": "proxy-secret",
        },
        verify_tls=True,
        chunk_size=256 * 1024,
        timeout=30,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(TusError, match="cross-origin upload blocked"):
        await uploader.upload(path)

    # Only the configured Traxx create endpoint was contacted. No PATCH/HEAD
    # request — and therefore no bearer/proxy header or file bytes — reached
    # the server-controlled external Location.
    assert [request.url.host for request in requests] == ["traxx.example"]
