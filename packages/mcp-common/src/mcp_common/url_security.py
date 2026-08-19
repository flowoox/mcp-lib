from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit, urlunsplit


def parse_http_origin(value: str, *, allow_http: bool = True) -> SplitResult:
    raw = value.strip()
    parsed = urlsplit(raw)
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme.casefold() not in allowed_schemes:
        raise ValueError("URL must use an allowed HTTP(S) scheme")
    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URL userinfo is not allowed")
    if parsed.query or parsed.fragment:
        raise ValueError("Base URL must not contain a query or fragment")
    return parsed


def normalize_origin_url(value: str, *, allow_http: bool = True) -> str:
    parsed = parse_http_origin(value, allow_http=allow_http)
    if parsed.path not in {"", "/"}:
        raise ValueError("Base URL must be a bare origin without an application path")
    host = parsed.hostname or ""
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if parsed.scheme.casefold() == "https" else 80
    port = parsed.port
    netloc = rendered_host if port in {None, default_port} else f"{rendered_host}:{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, "", "", ""))


def origin_for_url(value: str, *, allow_http: bool = True) -> str:
    return normalize_origin_url(value, allow_http=allow_http)


def is_loopback_host(value: str) -> bool:
    parsed = parse_http_origin(value)
    hostname = (parsed.hostname or "").casefold()
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
