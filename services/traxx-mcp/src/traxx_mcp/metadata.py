from __future__ import annotations

import base64
import mimetypes
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mutagen import File as MutagenFile
from mutagen.aiff import AIFF
from mutagen.flac import FLAC, Picture
from mutagen.id3 import (
    APIC,
    ID3,
    TALB,
    TCON,
    TDRC,
    TIT2,
    TPE1,
    TPE2,
    TPOS,
    TRCK,
    ID3NoHeaderError,
)
from mutagen.mp4 import MP4, MP4Cover
from mutagen.wave import WAVE

AUDIO_EXTENSIONS = {
    ".flac",
    ".wav",
    ".aiff",
    ".aif",
    ".ape",
    ".wv",
    ".mp3",
    ".m4a",
    ".mp4",
    ".ogg",
    ".opus",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
COVER_NAMES = (
    "cover",
    "folder",
    "front",
    "album",
    "artwork",
    "albumart",
)
LEADING_TRACK_RE = re.compile(
    r"^\s*(?:(?P<disc>\d{1,2})[-_. ])?(?P<track>\d{1,3})\s*[-_. )]+\s*",
    re.IGNORECASE,
)
DISC_DIR_RE = re.compile(r"^(?:cd|disc|disk|part)\s*[-_. ]*(\d{1,2})$", re.IGNORECASE)


@dataclass(slots=True)
class LocalAudioMetadata:
    title: str
    artist: str
    album: str
    duration_ms: int
    track_number: int
    disc_number: int
    genres: list[str]
    release_date: str = ""
    has_cover: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TrackHint:
    title: str
    number: int
    disc_number: int = 1
    artist: str = ""
    artists: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> TrackHint:
        artists: list[str] = []
        raw_artists = value.get("artists")
        if isinstance(raw_artists, list):
            for item in raw_artists:
                if isinstance(item, dict):
                    name = str(item.get("name") or "").strip()
                else:
                    name = str(item or "").strip()
                if name and name not in artists:
                    artists.append(name)
        primary = str(value.get("artist") or "").strip()
        if primary and primary not in artists:
            artists.insert(0, primary)
        return cls(
            title=str(value.get("title") or value.get("name") or "").strip(),
            number=parse_number(str(value.get("number") or value.get("track_number") or "")),
            disc_number=parse_number(
                str(value.get("disc_number") or value.get("disc") or ""),
                default=1,
            ),
            artist=artists[0] if artists else primary,
            artists=artists,
        )


@dataclass(slots=True)
class TagWriteResult:
    path: str
    changed: bool
    cover_embedded: bool
    metadata: LocalAudioMetadata
    warnings: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "changed": self.changed,
            "cover_embedded": self.cover_embedded,
            "metadata": self.metadata.as_dict(),
            "warnings": self.warnings,
        }


def first_tag(tags: Any, *keys: str) -> str:
    if not tags:
        return ""
    for key in keys:
        try:
            value = tags.get(key)
        except AttributeError:
            value = None
        if value:
            if isinstance(value, (list, tuple)):
                value = value[0]
            return str(value)
    return ""


def parse_number(value: str, default: int = 1) -> int:
    match = re.search(r"\d+", value or "")
    return int(match.group(0)) if match else default


def infer_track_numbers(path: Path, album_root: Path | None = None) -> tuple[int, int]:
    match = LEADING_TRACK_RE.match(path.stem)
    track_number = int(match.group("track")) if match else 1
    disc_number = int(match.group("disc")) if match and match.group("disc") else 1
    root = album_root.resolve() if album_root else None
    for parent in path.parents:
        if root and parent.resolve() == root:
            break
        disc_match = DISC_DIR_RE.match(parent.name.strip())
        if disc_match:
            disc_number = int(disc_match.group(1))
            break
    return track_number, disc_number


def clean_title_from_filename(path: Path) -> str:
    title = LEADING_TRACK_RE.sub("", path.stem).replace("_", " ").strip(" -_.")
    return re.sub(r"\s+", " ", title) or path.stem


def _has_cover(audio: Any, suffix: str) -> bool:
    try:
        if suffix == ".flac":
            return bool(getattr(audio, "pictures", []))
        if suffix in {".m4a", ".mp4"}:
            return bool((audio.tags or {}).get("covr"))
        if suffix in {".mp3", ".wav", ".aif", ".aiff"}:
            tags = getattr(audio, "tags", None)
            return bool(tags and any(str(key).startswith("APIC") for key in tags))
        tags = getattr(audio, "tags", None) or {}
        return bool(tags.get("metadata_block_picture") or tags.get("coverart"))
    except Exception:
        return False


def _id3_text(tags: Any, key: str) -> str:
    if not tags:
        return ""
    frame = tags.get(key)
    if frame is None:
        return ""
    text = getattr(frame, "text", None)
    if isinstance(text, (list, tuple)) and text:
        return str(text[0])
    return str(text or "")


def inspect_audio_file(path: Path) -> LocalAudioMetadata:
    suffix = path.suffix.casefold()
    raw_audio = MutagenFile(path, easy=False)
    info = getattr(raw_audio, "info", None)
    duration_ms = int(max(1, float(getattr(info, "length", 0) or 0) * 1000))
    inferred_track, inferred_disc = infer_track_numbers(path)

    if suffix in {".mp3", ".wav", ".aif", ".aiff"}:
        tags = getattr(raw_audio, "tags", None) or {}
        genre_value = _id3_text(tags, "TCON")
        genres = [part.strip() for part in genre_value.split(",") if part.strip()]
        return LocalAudioMetadata(
            title=_id3_text(tags, "TIT2") or clean_title_from_filename(path),
            artist=_id3_text(tags, "TPE1") or _id3_text(tags, "TPE2") or "Unknown Artist",
            album=_id3_text(tags, "TALB") or path.parent.name,
            duration_ms=duration_ms,
            track_number=parse_number(_id3_text(tags, "TRCK"), default=inferred_track),
            disc_number=parse_number(_id3_text(tags, "TPOS"), default=inferred_disc),
            genres=genres,
            release_date=_id3_text(tags, "TDRC"),
            has_cover=_has_cover(raw_audio, suffix),
        )

    if suffix in {".m4a", ".mp4"}:
        tags = getattr(raw_audio, "tags", None) or {}
        def mp4_first(key: str) -> str:
            value = tags.get(key)
            if isinstance(value, list) and value:
                return str(value[0])
            return str(value or "")
        trkn = tags.get("trkn") or []
        disk = tags.get("disk") or []
        track_number = int(trkn[0][0]) if trkn else inferred_track
        disc_number = int(disk[0][0]) if disk else inferred_disc
        return LocalAudioMetadata(
            title=mp4_first("\xa9nam") or clean_title_from_filename(path),
            artist=mp4_first("\xa9ART") or mp4_first("aART") or "Unknown Artist",
            album=mp4_first("\xa9alb") or path.parent.name,
            duration_ms=duration_ms,
            track_number=track_number,
            disc_number=disc_number,
            genres=[str(value) for value in (tags.get("\xa9gen") or [])],
            release_date=mp4_first("\xa9day"),
            has_cover=_has_cover(raw_audio, suffix),
        )

    audio = MutagenFile(path, easy=True)
    tags = getattr(audio, "tags", {}) or {}
    genres_raw = tags.get("genre", []) if tags else []
    if isinstance(genres_raw, str):
        genres = [part.strip() for part in genres_raw.split(",") if part.strip()]
    else:
        genres = [str(item).strip() for item in genres_raw if str(item).strip()]
    return LocalAudioMetadata(
        title=first_tag(tags, "title") or clean_title_from_filename(path),
        artist=first_tag(tags, "artist", "albumartist") or "Unknown Artist",
        album=first_tag(tags, "album") or path.parent.name,
        duration_ms=duration_ms,
        track_number=parse_number(
            first_tag(tags, "tracknumber", "track"), default=inferred_track
        ),
        disc_number=parse_number(
            first_tag(tags, "discnumber", "disc"), default=inferred_disc
        ),
        genres=genres,
        release_date=first_tag(tags, "date", "year"),
        has_cover=_has_cover(raw_audio, suffix),
    )


def find_local_cover(album_root: Path) -> Path | None:
    images = [
        path
        for path in album_root.rglob("*")
        if path.is_file() and path.suffix.casefold() in IMAGE_EXTENSIONS
    ]
    if not images:
        return None

    def score(path: Path) -> tuple[int, int, int]:
        stem = path.stem.casefold().replace(" ", "")
        name_score = next(
            (100 - index for index, name in enumerate(COVER_NAMES) if name in stem),
            0,
        )
        root_score = 10 if path.parent.resolve() == album_root.resolve() else 0
        return name_score, root_score, path.stat().st_size

    return max(images, key=score)


def cover_mime_type(path: Path | None, data: bytes | None = None) -> str:
    if path:
        guessed = mimetypes.guess_type(path.name)[0]
        if guessed in {"image/jpeg", "image/png", "image/webp"}:
            return guessed
    if data:
        if data.startswith(b"\x89PNG"):
            return "image/png"
        if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
            return "image/webp"
    return "image/jpeg"


def choose_track_hint(
    path: Path,
    *,
    album_root: Path,
    hints: list[TrackHint],
    position: int = 0,
    total_files: int = 0,
) -> TrackHint | None:
    """Match one file to the entry of the release listing it belongs to.

    A rip and a shop listing disagree about numbering more often than they
    agree: a two-disc rip counts 1-01…1-07 and 2-01…2-06 while the shop lists
    the same release flat as 1…13. Matching on the track number alone then
    gives every disc-two file the title of a disc-one track — measured on
    "Hurra die Welt geht unter", six of thirteen tracks arrived under the wrong
    name and were then dropped as duplicates of the tracks they had been
    renamed to.

    ``position`` is the file's place in the sorted album folder and is used
    only when nothing else matched and the folder holds exactly as many files
    as the listing has entries.
    """
    if not hints:
        return None
    track_number, disc_number = infer_track_numbers(path, album_root)
    for hint in hints:
        if hint.number == track_number and hint.disc_number == disc_number:
            return hint
    same_track = [hint for hint in hints if hint.number == track_number]
    # Only when the discs agree. An unambiguous track number on the wrong disc
    # is not the same track.
    if len(same_track) == 1 and same_track[0].disc_number == disc_number:
        return same_track[0]
    normalized = clean_title_from_filename(path).casefold()
    by_title = next(
        (hint for hint in hints if hint.title and hint.title.casefold() in normalized),
        None,
    )
    if by_title is not None:
        return by_title
    if position and total_files and total_files == len(hints):
        return hints[position - 1]
    return None


def assign_track_hints(
    files: list[Path],
    *,
    album_root: Path,
    hints: list[TrackHint],
) -> dict[Path, TrackHint | None]:
    """Give every file of one folder its own entry from the listing.

    Decided for the folder as a whole, because a per-file decision cannot see
    that two files claimed the same entry. That is not a corner case: a rip
    named "Artist_Album_01_Title.flac" carries no *leading* number, so every
    file looks like track one, every file is matched to the first entry, and
    an album of ten arrives in Traxx as a single track — the other nine are
    recognised as duplicates of it and dropped.

    When the folder and the listing hold the same number of tracks, the sorted
    order settles it, since that is the order the release is in.
    """
    ordered = list(files)
    chosen: dict[Path, TrackHint | None] = {}
    for index, path in enumerate(ordered):
        chosen[path] = choose_track_hint(
            path,
            album_root=album_root,
            hints=hints,
            position=index + 1,
            total_files=len(ordered),
        )
    matched = [hint for hint in chosen.values() if hint is not None]
    distinct = {(hint.disc_number, hint.number, hint.title) for hint in matched}
    if len(hints) == len(ordered) and len(distinct) < len(matched):
        return {path: hints[index] for index, path in enumerate(ordered)}
    return chosen


def _set_easy_tags(
    path: Path,
    *,
    title: str,
    artists: list[str],
    album_artist: str,
    album: str,
    track_number: int,
    disc_number: int,
    release_date: str,
    genres: list[str],
) -> None:
    suffix = path.suffix.casefold()
    if suffix in {".mp3", ".wav", ".aif", ".aiff"}:
        if suffix == ".mp3":
            try:
                tags = ID3(path)
            except ID3NoHeaderError:
                tags = ID3()
        else:
            audio = WAVE(path) if suffix == ".wav" else AIFF(path)
            if audio.tags is None:
                audio.add_tags()
            tags = audio.tags
        for frame in ("TIT2", "TPE1", "TPE2", "TALB", "TRCK", "TPOS", "TDRC", "TCON"):
            tags.delall(frame)
        tags.add(TIT2(encoding=3, text=[title]))
        tags.add(TPE1(encoding=3, text=artists))
        tags.add(TPE2(encoding=3, text=[album_artist]))
        tags.add(TALB(encoding=3, text=[album]))
        tags.add(TRCK(encoding=3, text=[str(track_number)]))
        tags.add(TPOS(encoding=3, text=[str(disc_number)]))
        if release_date:
            tags.add(TDRC(encoding=3, text=[release_date]))
        if genres:
            tags.add(TCON(encoding=3, text=genres))
        if suffix == ".mp3":
            tags.save(path, v2_version=3)
        else:
            audio.save()
        return
    if suffix in {".m4a", ".mp4"}:
        audio = MP4(path)
        if audio.tags is None:
            audio.add_tags()
        audio["\xa9nam"] = [title]
        audio["\xa9ART"] = artists
        audio["aART"] = [album_artist]
        audio["\xa9alb"] = [album]
        audio["trkn"] = [(track_number, 0)]
        audio["disk"] = [(disc_number, 0)]
        if release_date:
            audio["\xa9day"] = [release_date]
        if genres:
            audio["\xa9gen"] = genres
        audio.save()
        return

    audio = MutagenFile(path, easy=True)
    if audio is None:
        raise ValueError(f"Unsupported audio file: {path}")
    if audio.tags is None:
        audio.add_tags()
    audio["title"] = [title]
    audio["artist"] = artists
    audio["albumartist"] = [album_artist]
    audio["album"] = [album]
    audio["tracknumber"] = [str(track_number)]
    audio["discnumber"] = [str(disc_number)]
    if release_date:
        audio["date"] = [release_date]
    if genres:
        audio["genre"] = genres
    audio.save()


def _id3_cover(path: Path, data: bytes, mime: str) -> None:
    suffix = path.suffix.casefold()
    if suffix == ".mp3":
        try:
            tags = ID3(path)
        except ID3NoHeaderError:
            tags = ID3()
        tags.delall("APIC")
        tags.add(APIC(encoding=3, mime=mime, type=3, desc="Cover", data=data))
        tags.save(path, v2_version=3)
        return
    audio = WAVE(path) if suffix == ".wav" else AIFF(path)
    if audio.tags is None:
        audio.add_tags()
    audio.tags.delall("APIC")
    audio.tags.add(APIC(encoding=3, mime=mime, type=3, desc="Cover", data=data))
    audio.save()


def _embed_cover(path: Path, data: bytes, mime: str) -> bool:
    suffix = path.suffix.casefold()
    if suffix == ".flac":
        audio = FLAC(path)
        picture = Picture()
        picture.type = 3
        picture.mime = mime
        picture.desc = "Cover"
        picture.data = data
        audio.clear_pictures()
        audio.add_picture(picture)
        audio.save()
        return True
    if suffix in {".mp3", ".wav", ".aif", ".aiff"}:
        _id3_cover(path, data, mime)
        return True
    if suffix in {".m4a", ".mp4"}:
        audio = MP4(path)
        image_format = (
            MP4Cover.FORMAT_PNG if mime == "image/png" else MP4Cover.FORMAT_JPEG
        )
        audio["covr"] = [MP4Cover(data, imageformat=image_format)]
        audio.save()
        return True
    if suffix in {".ogg", ".opus"}:
        audio = MutagenFile(path, easy=False)
        if audio is None:
            return False
        if audio.tags is None:
            audio.add_tags()
        picture = Picture()
        picture.type = 3
        picture.mime = mime
        picture.desc = "Cover"
        picture.data = data
        audio.tags["metadata_block_picture"] = [
            base64.b64encode(picture.write()).decode("ascii")
        ]
        audio.save()
        return True
    return False


def ensure_audio_metadata(
    path: Path,
    *,
    album_root: Path,
    artist: str,
    album: str,
    release_date: str = "",
    genres: list[str] | None = None,
    track_hints: list[dict[str, Any]] | None = None,
    cover_data: bytes | None = None,
    cover_mime: str = "image/jpeg",
    position: int = 0,
    total_files: int = 0,
    hint: TrackHint | None = None,
) -> TagWriteResult:
    before = inspect_audio_file(path)
    hints = [TrackHint.from_mapping(item) for item in (track_hints or [])]
    if hint is None:
        hint = choose_track_hint(
            path,
            album_root=album_root,
            hints=hints,
            position=position,
            total_files=total_files,
        )
    inferred_track, inferred_disc = infer_track_numbers(path, album_root)
    title = hint.title if hint and hint.title else before.title
    track_number = hint.number if hint else before.track_number or inferred_track
    disc_number = hint.disc_number if hint else before.disc_number or inferred_disc
    track_artists = list(hint.artists) if hint and hint.artists else []
    if not track_artists and hint and hint.artist:
        track_artists = [hint.artist]
    if not track_artists:
        track_artists = [artist or before.artist or "Unknown Artist"]
    effective_genres = list(genres or before.genres)
    warnings: list[str] = []

    _set_easy_tags(
        path,
        title=title,
        artists=track_artists,
        album_artist=artist or before.artist,
        album=album,
        track_number=max(1, track_number),
        disc_number=max(1, disc_number),
        release_date=release_date,
        genres=effective_genres,
    )
    cover_embedded = False
    if cover_data:
        try:
            cover_embedded = _embed_cover(path, cover_data, cover_mime)
            if not cover_embedded:
                warnings.append(f"Cover embedding is not supported for {path.suffix}")
        except Exception as exc:
            warnings.append(f"Cover embedding failed: {exc}")

    after = inspect_audio_file(path)
    changed = before.as_dict() != after.as_dict()
    return TagWriteResult(
        path=str(path),
        changed=changed,
        cover_embedded=cover_embedded or after.has_cover,
        metadata=after,
        warnings=warnings,
    )
