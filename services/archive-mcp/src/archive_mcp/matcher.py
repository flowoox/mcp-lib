from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from mcp_common.http import get_case_insensitive
from mcp_common.paths import normalize_text, stable_id, token_overlap

from .licenses import LicenseVerdict
from .models import ArchiveFile

LOSSLESS_EXTENSIONS = {"flac", "wav", "aiff", "aif", "alac", "ape", "wv", "shn"}
LOSSY_EXTENSIONS = {"mp3", "m4a", "aac", "ogg", "oga", "opus", "wma"}
AUDIO_EXTENSIONS = LOSSLESS_EXTENSIONS | LOSSY_EXTENSIONS
# Files the Archive derives for its own player. They are audio, but taking
# them alongside the originals downloads every track two or three times.
DERIVATIVE_ONLY_FORMATS = {"64kbps mp3", "56kbps mp3", "ogg vorbis", "mpeg-4 audio"}

TRACK_RE = re.compile(r"^\s*(\d{1,3})")
DISC_RE = re.compile(r"^\s*(\d{1,2})\s*[-.]\s*(\d{1,3})\s*$")
MMSS_RE = re.compile(r"^\s*(?:(\d+):)?(\d{1,2}):(\d{1,2}(?:\.\d+)?)\s*$")
BITRATE_RE = re.compile(r"(\d{2,4})\s*kbps", re.IGNORECASE)


def parse_length(value: object) -> float | None:
    """Seconds out of what the Archive actually writes in ``length``.

    Measured on one single item (``gd66-12-01.sbd.sirmick...``) both spellings
    appear side by side: ``"04:32"`` for some files and ``"272.24"`` for
    others. Reading only one of them silently loses every duration of the
    other kind, and duration is what the importer checks a track against.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = MMSS_RE.match(text)
    if match:
        hours = float(match.group(1) or 0)
        return hours * 3600 + float(match.group(2)) * 60 + float(match.group(3))
    try:
        seconds = float(text)
    except ValueError:
        return None
    return seconds if seconds > 0 else None


def parse_track(value: object) -> tuple[int | None, int | None]:
    """Track and disc number out of the ``track`` field.

    The Archive writes ``"1"`` on some items and ``"1/9"`` on others — both
    appear in the sample — and multi-disc rips use ``"2-05"``. Splitting on
    "/" first is what keeps ``"1/9"`` from being read as track 19 or dropped.
    """
    if value is None:
        return None, None
    text = str(value).strip()
    if not text:
        return None, None
    head = text.split("/", 1)[0].strip()
    disc_match = DISC_RE.match(head)
    if disc_match:
        return int(disc_match.group(2)), int(disc_match.group(1))
    match = TRACK_RE.match(head)
    if not match:
        return None, None
    return int(match.group(1)), None


def parse_bitrate(record: dict[str, Any]) -> int | None:
    """kbit/s from the explicit field, else from the format name."""
    raw = get_case_insensitive(record, "bitrate", "bit_rate")
    if raw is not None:
        try:
            value = int(float(str(raw)))
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            # Some items report bit/s rather than kbit/s.
            return value // 1000 if value > 10000 else value
    match = BITRATE_RE.search(str(get_case_insensitive(record, "format", default="")))
    return int(match.group(1)) if match else None


def extension_of(name: str) -> str:
    return PurePosixPath(str(name or "")).suffix.lstrip(".").casefold()


def build_file(record: dict[str, Any]) -> ArchiveFile | None:
    """One audio file, or None when the record is not audio at all."""
    name = str(get_case_insensitive(record, "name", default="") or "")
    if not name:
        return None
    extension = extension_of(name)
    if extension not in AUDIO_EXTENSIONS:
        return None
    try:
        size = int(str(get_case_insensitive(record, "size", default=0) or 0))
    except (TypeError, ValueError):
        size = 0
    track, disc = parse_track(get_case_insensitive(record, "track"))
    return ArchiveFile(
        name=name,
        # The Archive spells the same format both "FLAC" and "Flac" — the
        # search index uses the first, the item metadata the second. Folding
        # the case here is what keeps a FLAC album from looking format-less.
        format=str(get_case_insensitive(record, "format", default="") or "").strip(),
        source=str(get_case_insensitive(record, "source", default="") or "").casefold(),
        size=max(0, size),
        md5=str(get_case_insensitive(record, "md5", default="") or "").strip().casefold(),
        extension=extension,
        length_seconds=parse_length(get_case_insensitive(record, "length")),
        track=track,
        disc=disc,
        title=str(get_case_insensitive(record, "title", default="") or "").strip(),
        bit_rate=parse_bitrate(record),
    )


def _format_rank(file: ArchiveFile, preferred: list[str]) -> tuple[int, int, int]:
    """Sort key that picks one file per track: better format, original first."""
    try:
        position = preferred.index(file.extension)
    except ValueError:
        position = len(preferred)
    is_original = 0 if file.source == "original" else 1
    if str(file.format or "").casefold() in DERIVATIVE_ONLY_FORMATS:
        is_original = 2
    return (position, is_original, -file.size)


def _dedup_key(file: ArchiveFile) -> str:
    """What makes two files the same track once derivatives are gone.

    The stem, because the Archive derives ``x.ogg`` from ``x.mp3`` — the
    extension is then the only difference. The full path is used so that
    ``cd1/01`` and ``cd2/01`` stay two tracks.
    """
    return PurePosixPath(file.name).with_suffix("").as_posix().casefold()


def drop_derivatives(files: list[ArchiveFile]) -> list[ArchiveFile]:
    """Keep the uploaded files and throw the Archive's transcodes away.

    Measured on ``crea002CandyPanda-androGigolo`` and ``GOD06``: one uploaded
    track carries up to three derivatives, and only *some* of them share the
    original's stem. ``01-Floor-A.mp3`` is joined by ``01-Floor-A.ogg`` (same
    stem) **and** by ``01-Floor-A_64kb.mp3`` (different stem, and no track
    number at all). Neither the stem nor the track number catches every case,
    so the ``source`` field is the only reliable rule — without it an album
    arrives two to three times over.

    Items whose originals were removed keep their derivatives; there is
    nothing else to offer there.
    """
    originals = [file for file in files if file.source == "original"]
    return originals or files


def select_album_files(
    records: list[dict[str, Any]],
    *,
    preferred_formats: list[str],
    lossless_only: bool,
    minimum_lossy_bitrate_kbps: int,
) -> tuple[list[ArchiveFile], list[str]]:
    """One file per track, after the quality gate. Also says what was dropped."""
    audio = [file for record in records if (file := build_file(record)) is not None]
    rejected: list[str] = []
    candidates: list[ArchiveFile] = []
    for file in drop_derivatives(audio):
        if lossless_only and file.extension not in LOSSLESS_EXTENSIONS:
            rejected.append(
                f"{PurePosixPath(file.name).name}: {file.extension} ist verlustbehaftet"
            )
            continue
        if (
            not lossless_only
            and file.extension in LOSSY_EXTENSIONS
            and file.bit_rate is not None
            and file.bit_rate < minimum_lossy_bitrate_kbps
        ):
            rejected.append(
                f"{PurePosixPath(file.name).name}: {file.bit_rate} kbps unter "
                f"{minimum_lossy_bitrate_kbps} kbps"
            )
            continue
        candidates.append(file)

    best: dict[str, ArchiveFile] = {}
    for file in candidates:
        key = _dedup_key(file)
        current = best.get(key)
        if current is None or _format_rank(file, preferred_formats) < _format_rank(
            current, preferred_formats
        ):
            best[key] = file
    chosen = sorted(
        best.values(),
        key=lambda item: (item.disc or 1, item.track or 10_000, item.name.casefold()),
    )
    return chosen, rejected


def score_candidate(
    *,
    artist: str,
    album: str,
    item_title: str,
    item_creator: str,
    files: list[ArchiveFile],
    expected_track_count: int | None,
    verdict: LicenseVerdict,
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = token_overlap(album, item_title) * 45 + token_overlap(artist, item_creator) * 30
    reasons.append(
        f"Titel-/Künstlerdeckung {token_overlap(album, item_title):.2f}/"
        f"{token_overlap(artist, item_creator):.2f}"
    )
    if normalize_text(album) and normalize_text(album) == normalize_text(item_title):
        score += 15
        reasons.append("Albumtitel exakt")
    if normalize_text(artist) and normalize_text(artist) == normalize_text(item_creator):
        score += 10
        reasons.append("Künstler exakt")
    if expected_track_count:
        if len(files) == expected_track_count:
            score += 20
            reasons.append(f"Titelzahl passt ({expected_track_count})")
        else:
            score -= min(20, abs(len(files) - expected_track_count) * 4)
            reasons.append(f"{len(files)} statt {expected_track_count} Titel")
    lossless = sum(1 for file in files if file.extension in LOSSLESS_EXTENSIONS)
    if lossless == len(files) and files:
        score += 12
        reasons.append("durchgehend verlustfrei")
    if all(file.md5 for file in files) and files:
        # Every file can be verified after transfer, which no peer network
        # offers. Worth preferring when two items are otherwise equal.
        score += 5
        reasons.append("Prüfsummen vorhanden")
    if verdict.basis == "public-domain":
        score += 4
        reasons.append("gemeinfrei")
    return round(score, 3), reasons


def candidate_id_for(identifier: str, files: list[ArchiveFile]) -> str:
    return stable_id("archive", identifier, len(files), files[0].name if files else "")


def extract_search_docs(payload: Any) -> list[dict[str, Any]]:
    response = get_case_insensitive(payload, "response", default={})
    docs = get_case_insensitive(response, "docs", default=[])
    return [doc for doc in docs if isinstance(doc, dict)] if isinstance(docs, list) else []


def coerce_list(value: Any) -> list[str]:
    """``collection`` and ``creator`` come as a string or a list of strings.

    Measured: ``cz-ogreatqueenelectric`` answers with a list, the
    ``freemusicarchive`` item with a bare string. Treating the string as a
    sequence would turn it into a list of single characters.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]
