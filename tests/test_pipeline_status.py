from mcp_lib.pipeline import classify_download_batch


def test_complete_batch() -> None:
    payload = {
        "files": [
            {"filename": "01.flac", "state": "Completed", "size": 100, "bytesTransferred": 100},
            {"filename": "02.flac", "state": "Completed", "size": 100, "bytesTransferred": 100},
        ]
    }
    assert classify_download_batch(payload) == "complete"


def test_active_batch_wins_over_failed_file() -> None:
    payload = {
        "files": [
            {"filename": "01.flac", "state": "Downloading"},
            {"filename": "02.flac", "state": "Errored"},
        ]
    }
    assert classify_download_batch(payload) == "active"


def test_failed_batch() -> None:
    payload = {"files": [{"filename": "01.flac", "state": "Rejected"}]}
    assert classify_download_batch(payload) == "failed"
