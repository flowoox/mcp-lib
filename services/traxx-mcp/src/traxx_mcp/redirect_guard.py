"""Fail-closed redirect policy for credential-bearing Traxx requests.

TraxxClient historically enabled httpx automatic redirects while attaching both
its bearer token and deployment-owned ``extra_headers``.  httpx protects the
standard Authorization header across many cross-origin redirects, but generic
proxy/WAF credentials are not a safe cross-origin trust boundary.  Install this
policy at package import so ordinary API calls and TUS endpoint discovery never
emit a second request to a server-controlled redirect destination.
"""

from __future__ import annotations

from typing import Any

import httpx

from .client import TUS_ENDPOINT_CANDIDATES, TraxxClient, TraxxError
from .tus import TusUnsupported

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


async def resolve_tus_endpoint_fail_closed(self: TraxxClient) -> str:
    """Discover the TUS path without forwarding credentials through redirects."""
    if self._tus_endpoint:
        return self._tus_endpoint
    if not self.config.base_url:
        raise TraxxError("Traxx URL is not configured")

    checked: list[str] = []
    seen: set[str] = set()
    async with httpx.AsyncClient(
        base_url=self.config.base_url,
        headers=self.headers,
        verify=self.config.verify_tls,
        timeout=self.config.timeout_seconds,
        follow_redirects=False,
    ) as client:
        for candidate in (self.config.tus_endpoint, *TUS_ENDPOINT_CANDIDATES):
            path = candidate.strip()
            if not path:
                continue
            if not path.startswith("/"):
                path = f"/{path}"
            path = path.rstrip("/") or "/"
            if path in seen:
                continue
            seen.add(path)
            try:
                response = await client.request("OPTIONS", path)
            except httpx.HTTPError as exc:
                checked.append(f"{path}: {type(exc).__name__}")
                continue
            if 300 <= response.status_code < 400:
                checked.append(f"{path}: {response.status_code} redirect refused")
                continue
            headers = {k.casefold(): v for k, v in response.headers.items()}
            if headers.get("tus-resumable") or headers.get("tus-version"):
                self._tus_endpoint = path
                return path
            checked.append(f"{path}: {response.status_code} without TUS headers")

    raise TusUnsupported(
        "No TUS upload route answered on this Traxx instance. Tried "
        + "; ".join(checked),
        status_code=0,
    )


def install() -> None:
    """Install the package-wide credential-bearing redirect boundary exactly once."""
    TraxxClient.request = request_fail_closed  # type: ignore[method-assign]
    TraxxClient._resolve_tus_endpoint = (  # type: ignore[method-assign]
        resolve_tus_endpoint_fail_closed
    )
