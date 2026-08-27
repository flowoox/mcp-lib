from pathlib import Path

from traxx_mcp.metadata import (
    TrackHint,
    duration_mismatch,
    title_conflict,
    verify_assignment,
    verify_release_coverage,
)


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


def test_the_filename_catches_what_a_rewritten_tag_hides() -> None:
    """The importer writes the expected title into the source file, so after
    one wrong run the tag agrees with the listing while the audio does not.
    Only the name the stranger gave the file survives that.
    """
    path = Path("/downloads/Onative/sleeping/01. Onative - How.flac")
    hint = TrackHint(title="sleeping", number=1)

    rejected = verify_assignment(
        {path: hint}, {path: 138_300}, observed_titles={path: "Onative - How"}
    )

    assert path in rejected
    assert "kein gemeinsames Wort" in rejected[path]


def test_a_known_length_outranks_a_differently_named_file() -> None:
    # Rips name their files freely. Once the length agrees, the name says
    # nothing more about whether this is the right recording.
    path = Path("/downloads/x/07 - Artist - Title (Remastered 2011).flac")
    hint = TrackHint(title="Title", number=7, duration_ms=200_000)

    assert verify_assignment(
        {path: hint}, {path: 201_000}, observed_titles={path: "Etwas ganz anderes"}
    ) == {}


def test_titles_survive_the_usual_rip_decorations() -> None:
    assert not title_conflict("Wir", "Wir")
    assert not title_conflict("Ariane", "K.I.Z - Ariane")
    assert not title_conflict("Boom Boom Boom", "Boom Boom Boom (Live)")
    assert not title_conflict("Superstars", "Superstars feat. Henning May")
    # A bare number carries no information and must not reject anything.
    assert not title_conflict("Wir", "01")
    assert title_conflict("sleeping", "Onative / zubi - How")


def test_release_coverage_allows_duplicate_files_but_counts_tracks_once() -> None:
    files = {
        Path("/downloads/a/01 Gosh.flac"): 293_000,
        Path("/downloads/a/01 Gosh duplicate.flac"): 293_500,
        Path("/downloads/a/02 Sleep Sound.flac"): 229_000,
        Path("/downloads/a/02 Sleep Sound duplicate.flac"): 228_500,
    }
    hints = [
        TrackHint(title="Gosh", number=1, duration_ms=293_000),
        TrackHint(title="Sleep Sound", number=2, duration_ms=229_000),
    ]

    result = verify_release_coverage(
        files,
        hints,
        observed_titles={path: path.stem for path in files},
    )

    assert result["complete"] is True
    assert result["expected_tracks"] == 2
    assert result["matched_tracks"] == 2


def test_release_coverage_rejects_unrelated_folder_despite_similar_lengths() -> None:
    files = {
        Path("/downloads/a/01 Fish On Land.flac"): 231_000,
        Path("/downloads/a/02 Wallflower Edit.flac"): 268_000,
        Path("/downloads/a/03 Tokyo Edit.flac"): 146_000,
    }
    hints = [
        TrackHint(title="angelface", number=1, duration_ms=231_000),
        TrackHint(title="mean2me", number=2, duration_ms=268_000),
    ]

    result = verify_release_coverage(
        files,
        hints,
        observed_titles={path: path.stem for path in files},
    )

    assert result["complete"] is False
    assert result["matched_tracks"] == 0
    assert {item["title"] for item in result["missing"]} == {
        "angelface",
        "mean2me",
    }


def test_a_recorded_success_stops_answering_for_a_wrong_folder(tmp_path) -> None:
    """The ledger exists so a repeated import does not upload twice. It must
    not also certify an import made before the files were checked: otherwise
    a wrong recording stays "imported" forever and no retry can correct it.
    """
    from mcp_common.store import AtomicJsonStore

    from traxx_mcp.client import TraxxClient
    from traxx_mcp.config import RuntimeConfig

    downloads = tmp_path / "downloads"
    folder = downloads / "Onative" / "sleeping"
    folder.mkdir(parents=True)
    (folder / "01. Onative - How.flac").write_bytes(b"not really flac")

    client = TraxxClient(
        RuntimeConfig(base_url="https://example.test", token="t"),
        downloads_dir=downloads,
        import_ledger=AtomicJsonStore(tmp_path / "imports.json", default={}),
    )
    hints = [{"title": "sleeping", "number": 1}]

    # The filename shares no word with the expected title, so the folder
    # cannot be waved through on a recorded success.
    assert client.folder_fails_verification(folder, hints) is True


def test_a_folder_that_still_matches_keeps_its_recorded_success(tmp_path) -> None:
    from mcp_common.store import AtomicJsonStore

    from traxx_mcp.client import TraxxClient
    from traxx_mcp.config import RuntimeConfig

    downloads = tmp_path / "downloads"
    folder = downloads / "K.I.Z" / "Hurra"
    folder.mkdir(parents=True)
    (folder / "01 Wir.flac").write_bytes(b"not really flac")

    client = TraxxClient(
        RuntimeConfig(base_url="https://example.test", token="t"),
        downloads_dir=downloads,
        import_ledger=AtomicJsonStore(tmp_path / "imports.json", default={}),
    )

    # Unreadable audio means no duration, but the name agrees with the
    # listing, so nothing objects and the recorded result still stands.
    assert client.folder_fails_verification(folder, [{"title": "Wir", "number": 1}]) is False
