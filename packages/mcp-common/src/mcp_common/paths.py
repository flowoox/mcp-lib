from __future__ import annotations

import hashlib
import re
import unicodedata
from pathlib import Path

INVALID_SEGMENT = re.compile(r"[^\w .()\[\]{}&+,'!-]+", re.UNICODE)
SPACE_RE = re.compile(r"\s+")
DISC_SEGMENT_RE = re.compile(
    r"^(?:cd|disc|disk|part)\s*[-_. ]*([0-9]{1,2})$",
    re.IGNORECASE,
)


def normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFKD", value or "")
    value = "".join(char for char in value if not unicodedata.combining(char))
    value = value.casefold().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return SPACE_RE.sub(" ", value).strip()


def token_overlap(left: str, right: str) -> float:
    a = set(normalize_text(left).split())
    b = set(normalize_text(right).split())
    return len(a & b) / max(1, len(a))


def stable_id(*parts: object, length: int = 24) -> str:
    payload = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def safe_segment(value: str, fallback: str = "unknown") -> str:
    value = INVALID_SEGMENT.sub("_", value).strip(" ._")
    value = SPACE_RE.sub(" ", value)
    return value[:160] or fallback


def safe_relative_destination(artist: str, album: str) -> str:
    return f"{safe_segment(artist)}/{safe_segment(album)}"


def resolve_contained_path(root: str | Path, value: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    resolved = candidate.resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise ValueError(f"Path escapes configured root: {value}")
    return resolved
