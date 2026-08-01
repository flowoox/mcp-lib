from __future__ import annotations

import math
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from .models import AlbumCandidate, RemoteFile
from .utils import (
    DISC_SEGMENT_RE,
    get_case_insensitive,
    normalize_text,
    stable_id,
    token_overlap,
)

AUDIO_EXTENSIONS = {
    "flac",
    "wav",
    "alac",
    "aiff",
    "aif",
    "ape",
    "wv",
    "mp3",
    "m4a",
    "ogg",
    "opus",
}
SIDECAR_EXTENSIONS = {
    "cue",
    "log",
    "jpg",
    "jpeg",
    "png",
    "webp",
    "pdf",
    "m3u",
    "m3u8",
    "txt",
    "nfo",
}
BLOCKED_EXTENSIONS = {
    "exe",
    "msi",
    "bat",
    "cmd",
    "com",
    "scr",
    "ps1",
    "vbs",
    "js",
    "jar",
    "lnk",
}
LOSSLESS_EXTENSIONS = {"flac", "wav", "alac", "aiff", "aif", "ape", "wv"}


def normalize_remote_path(filename: str) -> PurePosixPath:
    path = filename.replace("\\", "/").replace("//", "/")
    return PurePosixPath(path.lstrip("/"))


def collapse_disc_folder(folder: PurePosixPath) -> tuple[PurePosixPath, int | None]:
    if not folder.parts:
        return folder, None
    match = DISC_SEGMENT_RE.match(folder.name.strip())
    if match and folder.parent != PurePosixPath("."):
        return folder.parent, int(match.group(1))
    return folder, None


def _extract_files(response: dict[str, Any]) -> list[dict[str, Any]]:
    files = get_case_insensitive(response, "files", "results", default=[])
    if isinstance(files, dict):
        flattened: list[dict[str, Any]] = []
        for value in files.values():
            if isinstance(value, list):
                flattened.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                flattened.append(value)
        return flattened
    if isinstance(files, list):
        return [item for item in files if isinstance(item, dict)]
    return []


def extract_search_responses(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    responses = get_case_insensitive(payload, "responses", "searchResponses", default=[])
    if isinstance(responses, list):
        return [item for item in responses if isinstance(item, dict)]
    if isinstance(responses, dict):
        output: list[dict[str, Any]] = []
        for username, value in responses.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("username", username)
                output.append(item)
            elif isinstance(value, list):
                output.append({"username": username, "files": value})
        return output

    # Some versions return one response object directly.
    if _extract_files(payload):
        return [payload]
    return []


def _remote_file(raw: dict[str, Any]) -> RemoteFile | None:
    filename = str(
        get_case_insensitive(raw, "filename", "fileName", "name", default="") or ""
    ).strip()
    if not filename:
        return None
    path = normalize_remote_path(filename)
    extension = path.suffix.lower().lstrip(".")
    if extension in BLOCKED_EXTENSIONS:
        return None
    try:
        size = int(get_case_insensitive(raw, "size", "fileSize", default=0) or 0)
    except (TypeError, ValueError):
        size = 0

    def optional_int(*keys: str) -> int | None:
        value = get_case_insensitive(raw, *keys)
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    return RemoteFile(
        filename=filename,
        size=size,
        extension=extension,
        bit_rate=optional_int("bitRate", "bitrate"),
        sample_rate=optional_int("sampleRate", "samplerate"),
        bit_depth=optional_int("bitDepth", "bitdepth"),
    )


def _score_candidate(
    *,
    artist: str,
    album: str,
    folder: str,
    files: list[RemoteFile],
    preferred_formats: list[str],
    free_upload_slots: bool | None,
    upload_speed: int | None,
    queue_length: int | None,
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    normalized_folder = normalize_text(folder)
    normalized_album = normalize_text(album)
    normalized_artist = normalize_text(artist)

    album_overlap = token_overlap(album, folder)
    artist_overlap = token_overlap(artist, folder)
    score += album_overlap * 45
    score += artist_overlap * 22
    if normalized_album and normalized_album in normalized_folder:
        score += 24
        reasons.append("album name matches folder")
    if normalized_artist and normalized_artist in normalized_folder:
        score += 12
        reasons.append("artist matches folder")

    audio_files = [file for file in files if file.extension in AUDIO_EXTENSIONS]
    formats = {file.extension for file in audio_files}
    if not formats:
        return -1000, ["no supported audio files"]

    preference = {extension.casefold(): index for index, extension in enumerate(preferred_formats)}
    best_rank = min((preference.get(extension, len(preference) + 5) for extension in formats))
    format_bonus = max(0, 25 - (best_rank * 2.5))
    score += format_bonus
    reasons.append(f"format: {', '.join(sorted(formats))}")

    if formats <= LOSSLESS_EXTENSIONS:
        score += 18
        reasons.append("lossless source")
    if len(formats) == 1:
        score += 7
        reasons.append("consistent audio format")

    track_count = len(audio_files)
    if 6 <= track_count <= 30:
        score += 15
    elif 4 <= track_count <= 60:
        score += 8
    else:
        score -= min(abs(track_count - 14), 20)
    reasons.append(f"{track_count} audio files")

    if any((file.bit_depth or 0) >= 24 for file in audio_files):
        score += 4
        reasons.append("high-resolution bit depth")

    if free_upload_slots is True:
        score += 12
        reasons.append("free upload slot")
    elif free_upload_slots is False:
        score -= 3

    if upload_speed and upload_speed > 0:
        score += min(12, math.log10(max(upload_speed, 1)) * 2)
    if queue_length is not None:
        score -= min(14, max(0, queue_length) * 0.4)

    # Avoid giant discographies accidentally grouped as one album.
    if track_count > 60:
        score -= 35
        reasons.append("possible discography/collection")

    return round(score, 3), reasons


def build_album_candidates(
    *,
    payload: Any,
    artist: str,
    album: str,
    search_id: str | None,
    preferred_formats: list[str],
    minimum_tracks: int = 4,
) -> list[AlbumCandidate]:
    grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "files": {},
            "discs": set(),
            "free_upload_slots": None,
            "upload_speed": None,
            "queue_length": None,
        }
    )

    for response in extract_search_responses(payload):
        username = str(
            get_case_insensitive(response, "username", "userName", "user", default="") or ""
        ).strip()
        if not username:
            continue
        free_upload_slots = get_case_insensitive(
            response,
            "hasFreeUploadSlot",
            "freeUploadSlots",
            "freeSlot",
        )
        if isinstance(free_upload_slots, int) and not isinstance(free_upload_slots, bool):
            free_upload_slots = free_upload_slots > 0
        upload_speed = get_case_insensitive(response, "uploadSpeed", "speed")
        queue_length = get_case_insensitive(response, "queueLength", "queue")
        try:
            upload_speed = int(upload_speed) if upload_speed is not None else None
        except (TypeError, ValueError):
            upload_speed = None
        try:
            queue_length = int(queue_length) if queue_length is not None else None
        except (TypeError, ValueError):
            queue_length = None

        for raw_file in _extract_files(response):
            file = _remote_file(raw_file)
            if not file:
                continue
            if file.extension not in AUDIO_EXTENSIONS | SIDECAR_EXTENSIONS:
                continue
            path = normalize_remote_path(file.filename)
            if path.parent == PurePosixPath("."):
                continue
            root, disc_number = collapse_disc_folder(path.parent)
            key = (username, root.as_posix())
            group = grouped[key]
            group["files"][file.filename] = file
            if disc_number is not None:
                group["discs"].add(disc_number)
            group["free_upload_slots"] = free_upload_slots
            group["upload_speed"] = upload_speed
            group["queue_length"] = queue_length

    candidates: list[AlbumCandidate] = []
    for (username, folder), group in grouped.items():
        files = list(group["files"].values())
        audio_files = [file for file in files if file.extension in AUDIO_EXTENSIONS]
        if len(audio_files) < minimum_tracks:
            continue
        if len(audio_files) > 150:
            continue

        score, reasons = _score_candidate(
            artist=artist,
            album=album,
            folder=folder,
            files=files,
            preferred_formats=preferred_formats,
            free_upload_slots=group["free_upload_slots"],
            upload_speed=group["upload_speed"],
            queue_length=group["queue_length"],
        )
        candidate_id = stable_id(
            "slskd-album",
            username,
            folder,
            *sorted(f"{file.filename}:{file.size}" for file in files),
        )
        formats = sorted({file.extension for file in audio_files})
        candidates.append(
            AlbumCandidate(
                candidate_id=candidate_id,
                search_id=search_id,
                username=username,
                folder=folder,
                artist=artist,
                album=album,
                files=sorted(files, key=lambda item: normalize_remote_path(item.filename).as_posix()),
                audio_file_count=len(audio_files),
                total_file_count=len(files),
                disc_count=max(1, len(group["discs"])),
                formats=formats,
                total_bytes=sum(file.size for file in files),
                free_upload_slots=group["free_upload_slots"],
                upload_speed=group["upload_speed"],
                queue_length=group["queue_length"],
                score=score,
                score_reasons=reasons,
            )
        )

    candidates.sort(
        key=lambda candidate: (
            candidate.score,
            candidate.free_upload_slots is True,
            candidate.upload_speed or 0,
        ),
        reverse=True,
    )
    return candidates
