import pytest

from soulseek_mcp.client import classify_batch, sanitize_destination


def test_completed_batch():
    assert classify_batch({"files": [{"state": "Completed"}, {"state": "Completed"}]}) == "completed"


def test_failed_batch():
    assert classify_batch({"files": [{"state": "Rejected"}]}) == "failed"


@pytest.mark.parametrize(
    "state",
    [
        "Completed, Aborted",
        "Completed, Rejected",
        "Completed, Errored",
        "Completed, Cancelled",
    ],
)
def test_compound_terminal_failure_is_never_completed(state: str) -> None:
    assert classify_batch({"files": [{"state": state}]}) == "failed"


def test_active_batch():
    assert classify_batch({"files": [{"state": "Downloading"}]}) == "active"


def test_destination_is_sanitized() -> None:
    assert sanitize_destination("Artist: Name/Album * Deluxe") == "Artist_ Name/Album _ Deluxe"


def test_destination_rejects_escape() -> None:
    with pytest.raises(ValueError):
        sanitize_destination("../secret")
    with pytest.raises(ValueError):
        sanitize_destination("/absolute")
