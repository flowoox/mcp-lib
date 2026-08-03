from __future__ import annotations

import base64
import wave
from pathlib import Path

from traxx_mcp.client import extract_items, normalize_genres
from traxx_mcp.metadata import (
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
