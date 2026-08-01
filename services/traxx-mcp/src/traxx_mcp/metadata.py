from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mutagen import File as MutagenFile

AUDIO_EXTENSIONS = {".flac", ".wav", ".aiff", ".aif", ".ape", ".wv", ".mp3", ".m4a", ".ogg", ".opus"}


@dataclass(slots=True)
class LocalAudioMetadata:
    title: str
    artist: str
    album: str
    duration_ms: int
    track_number: int
    disc_number: int
    genres: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def first_tag(tags: Any, *keys: str) -> str:
    if not tags:
        return ""
    for key in keys:
        value = tags.get(key)
        if value:
            return str(value[0] if isinstance(value, list) else value)
    return ""


def parse_number(value: str, default: int = 1) -> int:
    match = re.search(r"\d+", value or "")
    return int(match.group(0)) if match else default


def inspect_audio_file(path: Path) -> LocalAudioMetadata:
    audio = MutagenFile(path, easy=True)
    tags = getattr(audio, "tags", {}) or {}
    info = getattr(audio, "info", None)
    duration_ms = int(max(1, float(getattr(info, "length", 0) or 0) * 1000))
    genres_raw = tags.get("genre", []) if tags else []
    if isinstance(genres_raw, str):
        genres = [part.strip() for part in genres_raw.split(",") if part.strip()]
    else:
        genres = [str(item).strip() for item in genres_raw if str(item).strip()]
    return LocalAudioMetadata(
        title=first_tag(tags, "title") or path.stem,
        artist=first_tag(tags, "albumartist", "artist") or "Unknown Artist",
        album=first_tag(tags, "album") or path.parent.name,
        duration_ms=duration_ms,
        track_number=parse_number(first_tag(tags, "tracknumber", "track")),
        disc_number=parse_number(first_tag(tags, "discnumber", "disc")),
        genres=genres,
    )
