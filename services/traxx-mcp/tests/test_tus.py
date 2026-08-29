from traxx_mcp.tus import TusUploader


def test_extracts_file_entry_from_headers():
    file_id, file_url = TusUploader.extract_identity({"X-File-Entry-Id": "42", "X-File-Url": "/storage/a.mp3"}, "https://x/api/tus/abc", None)
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


def test_external_upload_location_is_not_rewritten():
    result = TusUploader.resolve_upload_url(
        "http://bemusic-web:8080/api/v1/tus/upload",
        "http://bemusic-web:8080/api/v1/tus/upload",
        "https://uploads.example.net/tus/abc-1",
        {"Host": "traxx.tekoda.cloud"},
    )

    assert result == "https://uploads.example.net/tus/abc-1"
