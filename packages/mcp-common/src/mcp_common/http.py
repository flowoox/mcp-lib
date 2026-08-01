from __future__ import annotations

from typing import Any


def get_case_insensitive(mapping: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    lowered = {str(key).casefold(): value for key, value in mapping.items()}
    for key in keys:
        if key.casefold() in lowered:
            return lowered[key.casefold()]
    return default
