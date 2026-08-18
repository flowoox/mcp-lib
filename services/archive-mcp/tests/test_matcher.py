from archive_mcp.matcher import (
    build_file,
    coerce_list,
    parse_length,
    parse_track,
    select_album_files,
)

PREFERRED = ["flac", "wav", "aiff", "aif", "mp3", "ogg", "m4a"]


def test_length_is_read_in_both_spellings_the_archive_uses() -> None:
    """Measured on item ``gd66-12-01.sbd.sirmick.26968.sbeok.shnf``: the very
    same item writes ``"04:32"`` for some files and ``"272.24"`` for others.
    Supporting only one of them loses every duration of the other kind, and
    duration is what the Traxx import checks a track against."""
    assert parse_length("272.24") == 272.24
    assert parse_length("04:32") == 272.0
    assert parse_length("1:00:30") == 3630.0
    assert parse_length("") is None
    assert parse_length(None) is None
    assert parse_length("not a number") is None


def test_track_number_survives_the_slash_form() -> None:
    """``cz-ogreatqueenelectric`` writes ``"1/9"``, the freemusicarchive item
    writes ``"1"``. Reading the raw string as an int would drop the first and
    a naive digit scan would read it as 19."""
    assert parse_track("1/9") == (1, None)
    assert parse_track("1") == (1, None)
    assert parse_track("07") == (7, None)
    assert parse_track("2-05") == (5, 2)
    assert parse_track(None) == (None, None)
    assert parse_track("") == (None, None)


def test_format_case_does_not_decide_whether_a_file_is_audio() -> None:
    """The search index spells it ``FLAC``, the item metadata ``Flac``.
    The extension is what this connector actually keys on, so both survive."""
    for spelling in ("FLAC", "Flac", "flac"):
        file = build_file({"name": "01 - Song.flac", "format": spelling, "size": "10"})
        assert file is not None
        assert file.extension == "flac"


def test_non_audio_files_are_ignored() -> None:
    for name in ("cover.jpg", "item.m3u", "__ia_thumb.jpg", "meta.xml"):
        assert build_file({"name": name, "format": "JPEG"}) is None


def test_collection_may_be_a_string_or_a_list() -> None:
    """``cz-ogreatqueenelectric`` answers with a list, the freemusicarchive
    item with a bare string. Iterating the string would yield characters."""
    assert coerce_list(["netlabels", "community"]) == ["netlabels", "community"]
    assert coerce_list("freemusicarchive") == ["freemusicarchive"]
    assert coerce_list(None) == []
    assert coerce_list("") == []


def test_derivatives_never_double_the_album() -> None:
    """Verbatim file list of ``crea002CandyPanda-androGigolo``.

    One uploaded track carries three derivatives. ``01-Floor-A.ogg`` shares
    the original's stem, ``01-Floor-A_64kb.mp3`` does **not** and has no track
    number either — so neither stem nor track number catches every case and
    only ``source`` does. Without this the album arrives three times over.
    """
    records = [
        {"name": "01-Floor-A.mp3", "format": "VBR MP3", "source": "original", "track": "1", "size": "900"},
        {"name": "01-Floor-A.ogg", "format": "Ogg Vorbis", "source": "derivative", "size": "300"},
        {"name": "01-Floor-A_64kb.mp3", "format": "64Kbps MP3", "source": "derivative", "size": "200"},
        {"name": "02-liveInParis.mp3", "format": "VBR MP3", "source": "original", "track": "2", "size": "800"},
        {"name": "02-liveInParis.ogg", "format": "Ogg Vorbis", "source": "derivative", "size": "250"},
        {"name": "02-liveInParis_64kb.mp3", "format": "64Kbps MP3", "source": "derivative", "size": "180"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [file.name for file in files] == ["01-Floor-A.mp3", "02-liveInParis.mp3"]


def test_vbr_derivative_with_a_track_number_is_still_dropped() -> None:
    """Verbatim from ``GOD06``: here the ``_vbr`` and ``_64kb`` derivatives do
    carry the original's track number, so grouping by track would keep one of
    them and could even prefer it over the original."""
    records = [
        {"name": "01.mp3", "format": "VBR MP3", "source": "original", "track": "01", "size": "900"},
        {"name": "01.ogg", "format": "Ogg Vorbis", "source": "derivative", "track": "01", "size": "300"},
        {"name": "01_64kb.mp3", "format": "64Kbps MP3", "source": "derivative", "track": "01", "size": "200"},
        {"name": "01_vbr.mp3", "format": "VBR MP3", "source": "derivative", "track": "01", "size": "850"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [file.name for file in files] == ["01.mp3"]


def test_an_item_with_only_derivatives_still_offers_them() -> None:
    """Some items had their originals removed. Refusing to offer anything
    there would drop a usable release for a bookkeeping reason."""
    records = [
        {"name": "01.mp3", "format": "VBR MP3", "source": "derivative", "track": "1", "size": "900"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [file.name for file in files] == ["01.mp3"]


def test_non_numeric_track_fields_do_not_crash_the_selection() -> None:
    """``Michael_Renk_A_Eighth_Byte`` writes ``track: "GMIX 14/07"``."""
    records = [
        {"name": "a.mp3", "format": "VBR MP3", "source": "original", "track": "GMIX 14/07", "size": "9"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert len(files) == 1 and files[0].track is None


def test_flac_wins_over_the_mp3_derivative_of_the_same_track() -> None:
    records = [
        {"name": "01 - Song.flac", "format": "Flac", "source": "original", "track": "1/9", "size": "5000"},
        {"name": "01 - Song.mp3", "format": "VBR MP3", "source": "derivative", "track": "1/9", "size": "900"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [file.name for file in files] == ["01 - Song.flac"]


def test_lossless_only_reports_what_it_dropped() -> None:
    """An empty result has to be distinguishable from a strict gate, the same
    way the Soulseek connector reports its rejections."""
    records = [{"name": "01 - Song.mp3", "format": "VBR MP3", "source": "original", "track": "1"}]
    files, rejected = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=True, minimum_lossy_bitrate_kbps=128
    )
    assert files == []
    assert rejected and "verlustbehaftet" in rejected[0]


def test_low_bitrate_derivatives_are_dropped_by_the_bitrate_gate() -> None:
    """The Archive's ``64Kbps MP3`` derivative carries its bitrate only in the
    format name, not in a numeric field."""
    records = [
        {"name": "01 - Song.mp3", "format": "64Kbps MP3", "source": "derivative", "track": "1"},
    ]
    files, rejected = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert files == []
    assert rejected and "64 kbps" in rejected[0]


def test_files_without_track_numbers_are_still_deduplicated_by_stem() -> None:
    records = [
        {"name": "hc040_appflsoft.mp3", "format": "VBR MP3", "source": "original", "size": "100"},
        {"name": "hc040_appflsoft.ogg", "format": "Ogg Vorbis", "source": "derivative", "size": "50"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [file.name for file in files] == ["hc040_appflsoft.mp3"]


def test_multi_disc_tracks_are_ordered_by_disc_then_track() -> None:
    records = [
        {"name": "b.flac", "format": "Flac", "source": "original", "track": "2-01", "size": "1"},
        {"name": "a.flac", "format": "Flac", "source": "original", "track": "1-02", "size": "1"},
    ]
    files, _ = select_album_files(
        records, preferred_formats=PREFERRED, lossless_only=False, minimum_lossy_bitrate_kbps=128
    )
    assert [(file.disc, file.track) for file in files] == [(1, 2), (2, 1)]
