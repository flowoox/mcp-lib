from __future__ import annotations

import asyncio
import base64
import json
import time
from typing import Any

from .client import WazuhServerReadOnlyTransport
from .config import Settings

_TOKEN_REFRESH_SKEW_SECONDS = 30.0


def _jwt_expiration_epoch(token: str) -> float | None:
    """Read the unverified JWT exp claim only to shorten the local cache lifetime.

    Authorization is still enforced exclusively by the Wazuh server. A malformed or
    missing exp claim disables caching instead of extending token trust.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_segment = parts[1]
    try:
        padding = "=" * (-len(payload_segment) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_segment + padding))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    expiration: Any = payload.get("exp")
    if isinstance(expiration, bool) or not isinstance(expiration, (int, float)):
        return None
    value = float(expiration)
    return value if value > 0 else None


class ExpiringWazuhServerReadOnlyTransport(WazuhServerReadOnlyTransport):
    """Server transport that refreshes Wazuh JWTs before their advertised expiry."""

    def __init__(self, settings: Settings, **kwargs: Any) -> None:
        super().__init__(settings, **kwargs)
        self._jwt_valid_until_epoch = 0.0
        self._jwt_refresh_lock = asyncio.Lock()

    def _cached_token_is_fresh(self) -> bool:
        return bool(self._jwt) and time.time() < self._jwt_valid_until_epoch

    async def _authenticate(self, *, timeout_seconds: float, max_response_bytes: int) -> str:
        if self._cached_token_is_fresh():
            assert self._jwt is not None
            return self._jwt

        async with self._jwt_refresh_lock:
            if self._cached_token_is_fresh():
                assert self._jwt is not None
                return self._jwt

            # The base adapter otherwise caches indefinitely. Clear it before invoking
            # the fixed authentication request so expired/uncacheable tokens are renewed.
            self._jwt = None
            token = await super()._authenticate(
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            expiration = _jwt_expiration_epoch(token)
            if expiration is None:
                # Fail safe: use the token only for this request and re-authenticate on
                # the next operation rather than guessing a lifetime.
                self._jwt = None
                self._jwt_valid_until_epoch = 0.0
                return token

            self._jwt_valid_until_epoch = max(0.0, expiration - _TOKEN_REFRESH_SKEW_SECONDS)
            if not self._cached_token_is_fresh():
                # Very short-lived tokens remain usable for the current request but are
                # never cached past the refresh boundary.
                self._jwt = None
            return token
