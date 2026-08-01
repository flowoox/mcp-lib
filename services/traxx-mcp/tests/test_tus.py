from traxx_mcp.tus import TusUploader


def test_extracts_file_entry_from_headers():
    file_id, file_url = TusUploader.extract_identity({"X-File-Entry-Id": "42", "X-File-Url": "/storage/a.mp3"}, "https://x/api/tus/abc", None)
    assert file_id == "42"
    assert file_url == "/storage/a.mp3"


def test_extracts_numeric_id_from_location():
    file_id, _ = TusUploader.extract_identity({}, "https://x/api/tus/123", None)
    assert file_id == "123"
