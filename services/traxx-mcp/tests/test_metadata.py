from __future__ import annotations

import base64
import wave
from pathlib import Path

from traxx_mcp.client import extract_items, normalize_genres
from traxx_mcp.metadata import (
    TrackHint,
    choose_track_hint,
    clean_title_from_filename,
    ensure_audio_metadata,
    find_local_cover,
    infer_track_numbers,
    inspect_audio_file,
)

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl2nS0AAAAASUVORK5CYII="
)


def make_wav(path: Path) -> None:
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(b"\x00\x00" * 800)


def test_normalize_genres_from_resources():
    assert normalize_genres([{"id": 1, "name": "Rock"}, {"name": "Metal"}]) == [
        "Rock",
        "Metal",
    ]


def test_normalize_genres_uses_fallback():
    assert normalize_genres(None, ["Jazz"]) == ["Jazz"]


def test_extract_items_from_bemusic_pagination():
    assert extract_items({"pagination": {"data": [{"id": 4, "name": "Artist"}]}}) == [
        {"id": 4, "name": "Artist"}
    ]


def test_infers_disc_track_and_clean_title(tmp_path: Path):
    album = tmp_path / "Album"
    disc = album / "CD2"
    disc.mkdir(parents=True)
    path = disc / "03 - Final Song.wav"
    make_wav(path)
    assert infer_track_numbers(path, album) == (3, 2)
    assert clean_title_from_filename(path) == "Final Song"


def flat_listing() -> list[TrackHint]:
    """A shop listing of a two-disc release, counted straight through."""
    titles = [
        "Wir",
        "Geld",
        "Glücklich und satt",
        "Boom Boom Boom",
        "AMG Mercedes",
        "Freier Fall",
        "Ariane",
        "Käfigbett",
        "Verrückt nach dir",
        "Ehrenlos",
        "Superstars",
        "Was würde Manny Marc tun",
        "Hurra die Welt geht unter",
    ]
    return [
        TrackHint(title=title, number=index + 1, disc_number=1)
        for index, title in enumerate(titles)
    ]


def test_a_disc_two_file_does_not_take_a_disc_one_title(tmp_path: Path):
    album = tmp_path / "Hurra die Welt geht unter"
    album.mkdir()
    path = album / "2-02 Verrückt nach dir.flac"
    path.write_bytes(b"fLaC")

    hint = choose_track_hint(path, album_root=album, hints=flat_listing())

    # Matching on the track number alone would return "Geld", track two of
    # disc one, and the file would be imported under that name.
    assert hint is not None
    assert hint.title == "Verrückt nach dir"
    assert hint.number == 9


def test_position_resolves_a_rip_whose_names_say_nothing(tmp_path: Path):
    album = tmp_path / "Album"
    album.mkdir()
    path = album / "2-02 Track.flac"
    path.write_bytes(b"fLaC")

    hint = choose_track_hint(
        path,
        album_root=album,
        hints=flat_listing(),
        position=9,
        total_files=13,
    )

    assert hint is not None and hint.title == "Verrückt nach dir"


def test_a_single_disc_rip_still_matches_by_number(tmp_path: Path):
    album = tmp_path / "Album"
    album.mkdir()
    path = album / "02 Geld.flac"
    path.write_bytes(b"fLaC")

    hint = choose_track_hint(path, album_root=album, hints=flat_listing())

    assert hint is not None and hint.title == "Geld"


def test_prefers_named_local_cover(tmp_path: Path):
    (tmp_path / "random.jpg").write_bytes(b"small")
    (tmp_path / "cover.jpg").write_bytes(b"correct-cover")
    assert find_local_cover(tmp_path) == tmp_path / "cover.jpg"


def test_writes_fallback_tags_and_embeds_cover(tmp_path: Path):
    album = tmp_path / "Album"
    album.mkdir()
    path = album / "01 - Wrong Title.wav"
    make_wav(path)

    result = ensure_audio_metadata(
        path,
        album_root=album,
        artist="Correct Artist",
        album="Correct Album",
        release_date="2026-08-02",
        genres=["Electronic"],
        track_hints=[
            {
                "title": "Correct Title",
                "number": 1,
                "disc_number": 1,
                "artist": "Correct Artist",
            }
        ],
        cover_data=PNG_1X1,
        cover_mime="image/png",
    )

    metadata = inspect_audio_file(path)
    assert result.cover_embedded is True
    assert metadata.title == "Correct Title"
    assert metadata.artist == "Correct Artist"
    assert metadata.album == "Correct Album"
    assert metadata.track_number == 1
    assert metadata.disc_number == 1
    assert metadata.release_date.startswith("2026")
    assert metadata.has_cover is True


def test_track_artist_and_album_artist_are_written_separately(tmp_path: Path):
    from mutagen.wave import WAVE

    album = tmp_path / "Album"
    album.mkdir()
    path = album / "01 - Duet.wav"
    make_wav(path)

    ensure_audio_metadata(
        path,
        album_root=album,
        artist="Album Artist",
        album="Correct Album",
        track_hints=[
            {
                "title": "Duet",
                "number": 1,
                "disc_number": 1,
                "artist": "Guest Artist",
            }
        ],
    )

    metadata = inspect_audio_file(path)
    tags = WAVE(path).tags
    assert tags is not None
    assert metadata.artist == "Guest Artist"
    assert str(tags["TPE1"].text[0]) == "Guest Artist"
    assert str(tags["TPE2"].text[0]) == "Album Artist"


def test_track_hint_preserves_all_featured_artists() -> None:
    hint = TrackHint.from_mapping(
        {
            "title": "Collaboration",
            "number": 1,
            "artists": ["Main Artist", {"name": "Guest Artist"}],
        }
    )
    assert hint.artist == "Main Artist"
    assert hint.artists == ["Main Artist", "Guest Artist"]


def test_wav_tpe1_contains_all_track_artists(tmp_path: Path) -> None:
    from mutagen.wave import WAVE

    album = tmp_path / "Album"
    album.mkdir()
    path = album / "01 - Collaboration.wav"
    make_wav(path)
    ensure_audio_metadata(
        path,
        album_root=album,
        artist="Album Artist",
        album="Album",
        track_hints=[
            {
                "title": "Collaboration",
                "number": 1,
                "artists": ["Main Artist", "Guest Artist"],
            }
        ],
    )
    tags = WAVE(path).tags
    assert tags is not None
    assert list(tags["TPE1"].text) == ["Main Artist", "Guest Artist"]
    assert list(tags["TPE2"].text) == ["Album Artist"]
