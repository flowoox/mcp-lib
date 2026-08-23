from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .endpoints import ENDPOINTS, EntraEndpoint

_REDACTED = "[REDACTED]"
_MAX_DEPTH = 8
_MAX_ITEMS = 128
_MAX_STRING = 2048
_SECRET_SUFFIXES = ("password", "secret", "token", "privatekey", "clientsecret", "credential")


@dataclass
class SanitizeState:
    redacted: int = 0
    truncated: bool = False


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _is_secret(value: str) -> bool:
    normalized = _key(value)
    return any(normalized.endswith(suffix) for suffix in _SECRET_SUFFIXES)


def sanitize(value: Any, state: SanitizeState, *, field: str = "", depth: int = 0) -> Any:
    if _is_secret(field):
        state.redacted += 1
        return _REDACTED
    if depth > _MAX_DEPTH:
        state.truncated = True
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            state.truncated = True
            return value[:_MAX_STRING] + "…"
        return value
    if isinstance(value, Mapping):
        entries = list(value.items())
        if len(entries) > _MAX_ITEMS:
            entries = entries[:_MAX_ITEMS]
            state.truncated = True
        return {
            str(k): sanitize(v, state, field=str(k), depth=depth + 1)
            for k, v in entries
        }
    if isinstance(value, (list, tuple)):
        items = list(value)
        if len(items) > _MAX_ITEMS:
            items = items[:_MAX_ITEMS]
            state.truncated = True
        return [sanitize(item, state, depth=depth + 1) for item in items]
    return sanitize(str(value), state, field=field, depth=depth)


def project_record(endpoint: EntraEndpoint, record: Mapping[str, Any]) -> tuple[dict[str, Any], SanitizeState]:
    spec = ENDPOINTS[endpoint]
    state = SanitizeState()
    projected: dict[str, Any] = {}
    for field in spec.select_fields:
        if field in record:
            projected[field] = sanitize(record[field], state, field=field)
    return projected, state


def project_collection(endpoint: EntraEndpoint, payload: Mapping[str, Any], *, limit: int) -> dict[str, Any]:
    if isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    raw = payload.get("value")
    if not isinstance(raw, list):
        raise ValueError("Microsoft Graph collection response must contain a value array")
    items: list[dict[str, Any]] = []
    redacted = 0
    sanitization_truncated = False
    for record in raw[:limit]:
        if not isinstance(record, Mapping):
            continue
        projected, state = project_record(endpoint, record)
        items.append(projected)
        redacted += state.redacted
        sanitization_truncated = sanitization_truncated or state.truncated
    return {
        "items": items,
        "returned": len(items),
        "redactedFields": redacted,
        "sanitizationTruncated": sanitization_truncated,
    }
