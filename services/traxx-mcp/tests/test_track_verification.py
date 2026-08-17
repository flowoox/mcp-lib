from pathlib import Path

from traxx_mcp.metadata import TrackHint, duration_mismatch, verify_assignment


def test_a_different_recording_is_rejected() -> None:
    """The real case this exists for: a folder called "Onative / sleeping"
    held one file, "Onative / zubi - How". One file and one listed track, so
    position matched them, and the file was about to be published under the
    title "sleeping".
    """
    path = Path("/downloads/Onative/sleeping/01. Onative - How.flac")
    hint = TrackHint(title="sleeping", number=1, duration_ms=159_000)

    rejected = verify_assignment({path: hint}, {path: 138_300})

    assert path in rejected
    assert "andere" in rejected[path]
    assert "159" in rejected[path] and "138" in rejected[path]


def test_a_normal_mastering_difference_still_passes() -> None:
    # A CD rip and a streaming master rarely agree to the second; rejecting
    # those would block correct imports for no gain.
    assert duration_mismatch(210_000, 211_800) == 0
    assert duration_mismatch(210_000, 208_500) == 0


def test_a_missing_duration_is_not_an_objection() -> None:
    # Older recommendations carry hints without a length, and Traxx must stay
    # importable for them rather than refuse everything it cannot check.
    path = Path("/downloads/x/01.flac")
    assert verify_assignment({path: TrackHint(title="x", number=1)}, {path: 1000}) == {}
    assert duration_mismatch(0, 138_000) == 0
    assert duration_mismatch(159_000, 0) == 0


def test_short_tracks_get_an_absolute_floor() -> None:
    # Four percent of a 40 second interlude is under two seconds, which no
    # rip meets. The floor keeps the check from rejecting honest matches.
    assert duration_mismatch(40_000, 44_000) == 0
    assert duration_mismatch(40_000, 90_000) > 0


def test_a_hint_carries_the_duration_the_listing_gave() -> None:
    hint = TrackHint.from_mapping(
        {"title": "sleeping", "number": 1, "duration_ms": 159000}
    )
    assert hint.duration_ms == 159000
