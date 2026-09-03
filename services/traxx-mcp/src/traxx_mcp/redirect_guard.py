"""Fail-closed redirect policy for credential-bearing ordinary Traxx API calls.

TraxxClient historically enabled httpx automatic redirects while attaching both
its bearer token and deployment-owned ``extra_headers``.  httpx protects the
standard Authorization header across many cross-origin redirects, but generic
proxy/WAF credentials are not a safe cross-origin trust boundary.  Install this
policy at package import so every TraxxClient consumer gets the same behavior:
redirect responses are terminal errors and no second request is emitted.
"""

from __future__ import annotations

from typing import Any

import httpx

from .client import TraxxClient, TraxxError

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def request_fail_closed(
    self: TraxxClient,
    method: str,
    path: str,
    *,
    json: Any = None,
    params: dict[str, Any] | None = None,
    allow_error: bool = False,
) -> Any:
    """Send one Traxx API request without following any redirect.

    Redirects are rejected even for ``allow_error`` probes.  That option is for
    observing application error responses, not for authorizing a new network
    destination.  Mutating 3xx responses are marked ambiguous because the
    origin may already have committed before returning the redirect.
    """
    if not self.config.base_url:
        raise TraxxError("Traxx URL is not configured")

    normalized_method = method.upper()
    try:
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            verify=self.config.verify_tls,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
    except httpx.HTTPError as exc:
        mutation_ambiguous = normalized_method not in _SAFE_METHODS
        raise TraxxError(
            f"Traxx {normalized_method} {path} transport failed: {exc}",
            method=normalized_method,
            path=path,
            mutation_ambiguous=mutation_ambiguous,
        ) from exc

    if 300 <= response.status_code < 400:
        raise TraxxError(
            f"Traxx {normalized_method} {path} redirect refused "
            f"({response.status_code})",
            status_code=response.status_code,
            method=normalized_method,
            path=path,
            mutation_ambiguous=normalized_method not in _SAFE_METHODS,
        )

    if response.status_code >= 400 and not allow_error:
        raise TraxxError(
            f"Traxx {normalized_method} {path} failed ({response.status_code}): "
            f"{response.text[:1400]}",
            status_code=response.status_code,
            method=normalized_method,
            path=path,
            mutation_ambiguous=response.status_code >= 500
            or response.status_code == 408,
        )

    body: Any = None
    if response.content:
        try:
            body = response.json()
        except ValueError:
            body = {"text": response.text[:2000]}
    if allow_error:
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": body,
        }
    return body


def install() -> None:
    """Install the package-wide ordinary API redirect boundary exactly once."""
    if TraxxClient.request is request_fail_closed:
        return
    TraxxClient.request = request_fail_closed  # type: ignore[method-assign]
