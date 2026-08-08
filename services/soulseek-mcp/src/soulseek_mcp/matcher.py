from __future__ import annotations

import math
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from mcp_common.http import get_case_insensitive
from mcp_common.paths import DISC_SEGMENT_RE, normalize_text, stable_id, token_overlap

from .models import AlbumCandidate, RemoteFile

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
    "aac",
    "ogg",
    "opus",
}
LOSSLESS_EXTENSIONS = {"flac", "wav", "alac", "aiff", "aif", "ape", "wv"}
LOSSY_EXTENSIONS = AUDIO_EXTENSIONS - LOSSLESS_EXTENSIONS
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
    "apk",
    "sh",
}


def normalize_remote_path(filename: str) -> PurePosixPath:
    return PurePosixPath(filename.replace("\\", "/").replace("//", "/").lstrip("/"))


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
        output: list[dict[str, Any]] = []
        for value in files.values():
            if isinstance(value, list):
                output.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                output.append(value)
        return output
    return [item for item in files if isinstance(item, dict)] if isinstance(files, list) else []


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
    return [payload] if _extract_files(payload) else []


def _remote_file(raw: dict[str, Any]) -> RemoteFile | None:
    filename = str(
        get_case_insensitive(raw, "filename", "fileName", "name", default="") or ""
    ).strip()
    if not filename:
        return None
    path = normalize_remote_path(filename)
    extension = path.suffix.casefold().lstrip(".")
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


def bitrate_kbps(file: RemoteFile) -> int | None:
    """Normalize slskd bitrate values expressed as kbps or bits per second."""
    if not file.bit_rate or file.bit_rate <= 0:
        return None
    return round(file.bit_rate / 1000) if file.bit_rate > 10_000 else file.bit_rate


def is_high_quality_audio(
    file: RemoteFile,
    *,
    lossless_only: bool,
    minimum_lossy_bitrate_kbps: int,
) -> bool:
    if file.extension in LOSSLESS_EXTENSIONS:
        return True
    if lossless_only or file.extension not in LOSSY_EXTENSIONS:
        return False
    bitrate = bitrate_kbps(file)
    return bitrate is not None and bitrate >= minimum_lossy_bitrate_kbps


def _audio_track_key(file: RemoteFile) -> str:
    path = normalize_remote_path(file.filename)
    return path.with_suffix("").as_posix().casefold()


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
    score = token_overlap(album, folder) * 45 + token_overlap(artist, folder) * 22
    normalized_folder = normalize_text(folder)
    normalized_album = normalize_text(album)
    normalized_artist = normalize_text(artist)
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
    preference = {
        extension.casefold(): index for index, extension in enumerate(preferred_formats)
    }
    best_rank = min(
        preference.get(extension, len(preference) + 5) for extension in formats
    )
    score += max(0, 25 - best_rank * 2.5)
    reasons.append(f"format: {', '.join(sorted(formats))}")
    if formats <= LOSSLESS_EXTENSIONS:
        score += 28
        reasons.append("lossless-only source")
    if len(formats) == 1:
        score += 7
        reasons.append("consistent audio format")
    track_count = len(audio_files)
    score += (
        15
        if 6 <= track_count <= 30
        else 8
        if 4 <= track_count <= 60
        else -min(abs(track_count - 14), 20)
    )
    reasons.append(f"{track_count} audio files")
    if any((file.bit_depth or 0) >= 24 for file in audio_files):
        score += 6
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
    expected_track_count: int | None = None,
    lossless_only: bool = True,
    minimum_lossy_bitrate_kbps: int = 320,
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
            get_case_insensitive(
                response, "username", "userName", "user", default=""
            )
            or ""
        ).strip()
        if not username:
            continue
        free_slots = get_case_insensitive(
            response, "hasFreeUploadSlot", "freeUploadSlots", "freeSlot"
        )
        if isinstance(free_slots, int) and not isinstance(free_slots, bool):
            free_slots = free_slots > 0
        try:
            speed = int(get_case_insensitive(response, "uploadSpeed", "speed"))
        except (TypeError, ValueError):
            speed = None
        try:
            queue = int(get_case_insensitive(response, "queueLength", "queue"))
        except (TypeError, ValueError):
            queue = None
        for raw_file in _extract_files(response):
            remote = _remote_file(raw_file)
            if not remote or remote.extension not in AUDIO_EXTENSIONS | SIDECAR_EXTENSIONS:
                continue
            path = normalize_remote_path(remote.filename)
            if path.parent == PurePosixPath("."):
                continue
            root, disc = collapse_disc_folder(path.parent)
            group = grouped[(username, root.as_posix())]
            group["files"][remote.filename] = remote
            if disc is not None:
                group["discs"].add(disc)
            group.update(
                free_upload_slots=free_slots,
                upload_speed=speed,
                queue_length=queue,
            )

    candidates: list[AlbumCandidate] = []
    for (username, folder), group in grouped.items():
        all_files = list(group["files"].values())
        all_audio = [file for file in all_files if file.extension in AUDIO_EXTENSIONS]
        high_quality_audio = [
            file
            for file in all_audio
            if is_high_quality_audio(
                file,
                lossless_only=lossless_only,
                minimum_lossy_bitrate_kbps=minimum_lossy_bitrate_kbps,
            )
        ]
        preference = {
            extension.casefold(): index
            for index, extension in enumerate(preferred_formats)
        }
        selected_by_track: dict[str, RemoteFile] = {}
        for file in high_quality_audio:
            key = _audio_track_key(file)
            current = selected_by_track.get(key)
            rank = (
                preference.get(file.extension, len(preference) + 5),
                -(file.bit_depth or 0),
                -(file.sample_rate or 0),
                -file.size,
            )
            if current is None:
                selected_by_track[key] = file
                continue
            current_rank = (
                preference.get(current.extension, len(preference) + 5),
                -(current.bit_depth or 0),
                -(current.sample_rate or 0),
                -current.size,
            )
            if rank < current_rank:
                selected_by_track[key] = file
        accepted_audio = sorted(
            selected_by_track.values(),
            key=lambda item: normalize_remote_path(item.filename).as_posix(),
        )
        accepted_keys = set(selected_by_track)
        unique_rejected = [
            file for file in all_audio if _audio_track_key(file) not in accepted_keys
        ]
        if unique_rejected:
            continue
        track_count = len(accepted_audio)
        if track_count > 150:
            continue
        if expected_track_count and track_count != expected_track_count:
            continue
        if not expected_track_count and track_count < minimum_tracks:
            continue

        sidecars = [file for file in all_files if file.extension in SIDECAR_EXTENSIONS]
        files = accepted_audio + sidecars
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
        reasons.append(
            "quality gate: lossless only"
            if lossless_only
            else f"quality gate: lossy >= {minimum_lossy_bitrate_kbps} kbps"
        )
        if expected_track_count:
            reasons.append(f"track count matches expected: {expected_track_count}")
        candidates.append(
            AlbumCandidate(
                candidate_id=stable_id(
                    "slskd-album",
                    username,
                    folder,
                    *sorted(f"{file.filename}:{file.size}" for file in files),
                ),
                search_id=search_id,
                username=username,
                folder=folder,
                artist=artist,
                album=album,
                files=sorted(
                    files,
                    key=lambda item: normalize_remote_path(item.filename).as_posix(),
                ),
                audio_file_count=len(accepted_audio),
                total_file_count=len(files),
                disc_count=max(1, len(group["discs"])),
                formats=sorted({file.extension for file in accepted_audio}),
                total_bytes=sum(file.size for file in files),
                free_upload_slots=group["free_upload_slots"],
                upload_speed=group["upload_speed"],
                queue_length=group["queue_length"],
                score=score,
                score_reasons=reasons,
            )
        )
    return sorted(
        candidates,
        key=lambda item: (
            item.score,
            item.free_upload_slots is True,
            item.upload_speed or 0,
        ),
        reverse=True,
    )
