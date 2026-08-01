from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

SAFE_SEGMENT_RE = re.compile(r"[^\w .()\[\]{}&+'-]+", re.UNICODE)
MULTISPACE_RE = re.compile(r"\s+")
DISC_SEGMENT_RE = re.compile(r"^(?:cd|disc|disk|part)[ ._-]*(\d{1,2})$", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_now() -> str:
    return utc_now().isoformat()


def stable_id(*parts: object, length: int = 24) -> str:
    raw = "\x1f".join(str(part) for part in parts).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:length]


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).casefold()
    normalized = "".join(character for character in normalized if not unicodedata.combining(character))
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized)
    return MULTISPACE_RE.sub(" ", normalized).strip()


def token_overlap(left: str, right: str) -> float:
    left_tokens = set(normalize_text(left).split())
    right_tokens = set(normalize_text(right).split())
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def safe_segment(value: str, fallback: str = "unknown", max_length: int = 100) -> str:
    value = value.replace("/", "-").replace("\\", "-").strip()
    value = SAFE_SEGMENT_RE.sub("_", value)
    value = MULTISPACE_RE.sub(" ", value).strip(" ._")
    return (value or fallback)[:max_length]


def safe_relative_destination(*segments: str) -> str:
    cleaned = [safe_segment(segment) for segment in segments if segment.strip()]
    path = PurePosixPath(*cleaned)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Unsafe destination path")
    return path.as_posix()


def resolve_contained_path(root: Path, requested: str | Path) -> Path:
    root_resolved = root.resolve()
    requested_path = Path(requested)
    if not requested_path.is_absolute():
        requested_path = root_resolved / requested_path
    resolved = requested_path.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"Path must be inside {root_resolved}") from exc
    return resolved


def get_case_insensitive(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    lowered = {str(key).casefold(): value for key, value in mapping.items()}
    for key in keys:
        if key.casefold() in lowered:
            return lowered[key.casefold()]
    return default


def walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def parse_json(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
