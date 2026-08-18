"""A folder has to be able to be the release before any of it is imported."""

from __future__ import annotations

from pathlib import Path

from traxx_mcp.metadata import TrackHint, verify_release


def listing() -> list[TrackHint]:
    """An eight-track album, nothing shorter than two and a half minutes."""
    return [
        TrackHint(title=f"Track {index}", number=index, duration_ms=length)
        for index, length in enumerate(
            [212000, 154000, 198000, 231000, 175000, 189000, 205000, 167000], start=1
        )
    ]


def test_a_folder_of_drum_samples_is_not_the_album() -> None:
    # Measured on the live library: "Silhouettes" by Muted arrived as six
    # one-shot samples of about a second each and all six were published as
    # tracks of that album.
    samples = {Path(f"ethnicHigh_hit_{name}.wav"): 1200 for name in ("f", "mp", "pp")}
    samples.update({Path(f"ethnicLow_hit_{name}.wav"): 900 for name in ("f", "mp", "pp")})

    verdict = verify_release(samples, listing())

    assert verdict["checked"]
    assert verdict["reason"]
    assert "anderer Ordner" in verdict["reason"]


def test_a_real_rip_passes_even_when_a_track_is_missing() -> None:
    # Six of eight tracks, all of them plausible lengths: an incomplete rip is
    # still this album, and refusing it would throw away a good download.
    rip = {
        Path("01 Track.flac"): 212500,
        Path("02 Track.flac"): 153000,
        Path("03 Track.flac"): 199000,
        Path("04 Track.flac"): 230000,
        Path("05 Track.flac"): 176000,
        Path("06 Track.flac"): 188000,
    }

    verdict = verify_release(rip, listing())

    assert verdict["checked"]
    assert not verdict["reason"]
    assert verdict["foreign"] == []


def test_one_stray_file_does_not_condemn_the_folder() -> None:
    rip = {
        Path("01 Track.flac"): 212500,
        Path("02 Track.flac"): 153000,
        Path("03 Track.flac"): 199000,
        Path("interview.flac"): 900000,
    }

    verdict = verify_release(rip, listing())

    # Named, so the per-file check can still drop it, but the album itself is
    # not thrown away over one bonus file.
    assert str(Path("interview.flac")) in verdict["foreign"]
    assert not verdict["reason"]


def test_without_lengths_no_judgement_is_claimed() -> None:
    hints = [TrackHint(title="Track 1", number=1)]
    verdict = verify_release({Path("01 Track.flac"): 1200}, hints)

    # Saying "fine" without anything to compare against would be a lie the
    # caller cannot tell apart from a real pass.
    assert verdict["checked"] is False
    assert not verdict["reason"]


def test_a_single_wrong_track_is_caught() -> None:
    # "sleeping" by Onative: one file, and it is a different song entirely.
    single = [TrackHint(title="sleeping", number=1, duration_ms=168000)]
    verdict = verify_release({Path("01. Onative - How.flac"): 243000}, single)

    assert verdict["checked"]
    assert verdict["reason"]
