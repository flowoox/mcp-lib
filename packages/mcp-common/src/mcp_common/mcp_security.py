from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass
from secrets import compare_digest
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from jwt import InvalidTokenError
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings

LOCAL_HOSTS = ("127.0.0.1:*", "localhost:*", "[::1]:*")
LOCAL_ORIGINS = (
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
    "https://127.0.0.1:*",
    "https://localhost:*",
    "https://[::1]:*",
)
_OIDC_ALGORITHMS = ("RS256", "ES256")
_OIDC_METADATA_MAX_BYTES = 262_144
_OIDC_CACHE_SECONDS = 300.0
_SERVICE_SCOPES: dict[str, tuple[str, ...]] = {
    "mcp-fileshare": ("mcp.files.read",),
    "mcp-network": ("mcp.network.debug",),
    "mcp-veeam": ("mcp.infrastructure.observe",),
    "mcp-wazuh": ("mcp.infrastructure.observe",),
    "mcp-checkmk": ("mcp.infrastructure.observe",),
    "mcp-prtg": ("mcp.infrastructure.observe",),
    "mcp-hyperv": ("mcp.infrastructure.observe",),
    "mcp-windows": ("mcp.infrastructure.observe",),
}


def _csv(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value
    return [str(item).strip() for item in values if str(item).strip()]


def _origin(value: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("MCP_PUBLIC_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("MCP_PUBLIC_URL must not contain URL userinfo")
    return parsed.scheme, parsed.hostname, parsed.port


def _origin_text(value: str) -> str:
    scheme, host, port = _origin(value)
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if scheme == "https" else 80
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{scheme}://{rendered_host}{suffix}"


def _issuer_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("MCP_ISSUER_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP_ISSUER_URL must not contain userinfo, query, or fragment")
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("External OIDC issuer must use https")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _same_origin(left: str, right: str) -> bool:
    a = urlsplit(left)
    b = urlsplit(right)
    a_port = a.port or (443 if a.scheme == "https" else 80)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a.hostname, a_port) == (b.scheme, b.hostname, b_port)


def _oauth_metadata_url(issuer: str) -> str:
    parsed = urlsplit(issuer)
    suffix = parsed.path.rstrip("/")
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/.well-known/oauth-authorization-server{suffix}",
            "",
            "",
        )
    )


def _token_scopes(claims: dict[str, Any]) -> list[str]:
    scopes: set[str] = set()
    for name in ("scope", "scp"):
        value = claims.get(name)
        if isinstance(value, str):
            scopes.update(part for part in value.split() if part)
        elif isinstance(value, list):
            scopes.update(str(part).strip() for part in value if str(part).strip())
    roles = claims.get("roles")
    if isinstance(roles, str):
        scopes.add(roles.strip())
    elif isinstance(roles, list):
        scopes.update(str(role).strip() for role in roles if str(role).strip())
    return sorted(scopes)


def authenticated_actor(requested_actor: str) -> str:
    """Return a claim-bound audit actor when the current request uses OIDC.

    Static bootstrap auth and non-HTTP/unit-test contexts retain the caller-supplied
    actor. OIDC requests always ignore that value so a tool argument cannot forge
    the authenticated audit principal.
    """

    requested = str(requested_actor).strip()
    access_token = get_access_token()
    if access_token is None or access_token.subject is None:
        return requested

    claims = access_token.claims or {}
    if claims.get("_flowoox_auth_mode") != "oidc":
        return requested

    issuer = str(claims.get("iss", "")).strip()
    stable_subject = str(claims.get("oid") or access_token.subject).strip()
    if not issuer or not stable_subject:
        raise ValueError("OIDC access token is missing the immutable audit identity")

    display = ""
    for claim in ("preferred_username", "email", "name"):
        value = claims.get(claim)
        if isinstance(value, str) and value.strip():
            display = value.strip()
            break

    issuer_tag = hashlib.sha256(issuer.encode("utf-8")).hexdigest()[:12]
    principal = f"oidc:{issuer_tag}:{stable_subject}"
    if display:
        principal = f"{display[:64]} [{principal}]"
    return principal[:200]


class StaticBearerTokenVerifier(TokenVerifier):
    """Minimal verifier for an operator-provisioned MCP bootstrap bearer token."""

    def __init__(self, token: str, *, resource: str, scopes: Iterable[str]):
        if not token.strip():
            raise ValueError("MCP_AUTH_TOKEN must not be empty")
        self._token = token.strip()
        self._resource = resource
        self._scopes = list(dict.fromkeys(_csv(scopes))) or ["mcp"]

    async def verify_token(self, token: str) -> AccessToken | None:
        if not compare_digest(token, self._token):
            return None
        return AccessToken(
            token=token,
            client_id="configured-mcp-bootstrap-client",
            scopes=self._scopes,
            resource=self._resource,
            claims={"_flowoox_auth_mode": "static"},
        )


class OidcJwtTokenVerifier(TokenVerifier):
    """OIDC/OAuth resource-server verifier with fail-closed discovery and JWKS use."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        resource: str,
        required_scopes: Iterable[str],
    ) -> None:
        self._issuer = _issuer_url(issuer)
        self._audience = audience.strip()
        self._resource = resource
        self._required_scopes = frozenset(_csv(required_scopes))
        if not self._audience:
            raise ValueError("OIDC MCP authentication requires a non-empty audience")
        if not self._required_scopes:
            raise ValueError("OIDC MCP authentication requires at least one scope")
        self._jwks: list[dict[str, Any]] = []
        self._cache_expires = 0.0
        self._cache_lock = asyncio.Lock()

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        if not _same_origin(self._issuer, url):
            raise ValueError("OIDC discovery/JWKS URL must remain on the configured issuer origin")
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(5.0),
        ) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise ValueError("OIDC discovery/JWKS endpoint did not return HTTP 200")
        if len(response.content) > _OIDC_METADATA_MAX_BYTES:
            raise ValueError("OIDC discovery/JWKS response exceeded the size limit")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OIDC discovery/JWKS response must be a JSON object")
        return payload

    async def _refresh_jwks(self) -> None:
        now = time.monotonic()
        if self._jwks and now < self._cache_expires:
            return
        async with self._cache_lock:
            now = time.monotonic()
            if self._jwks and now < self._cache_expires:
                return

            metadata: dict[str, Any] | None = None
            discovery_urls = (
                f"{self._issuer}/.well-known/openid-configuration",
                _oauth_metadata_url(self._issuer),
            )
            for url in dict.fromkeys(discovery_urls):
                try:
                    candidate = await self._fetch_json(url)
                except (httpx.HTTPError, ValueError):
                    continue
                if str(candidate.get("issuer", "")).rstrip("/") != self._issuer:
                    continue
                metadata = candidate
                break
            if metadata is None:
                raise ValueError("OIDC authorization-server discovery failed closed")

            jwks_uri = str(metadata.get("jwks_uri", "")).strip()
            if not jwks_uri:
                raise ValueError("OIDC discovery metadata did not provide jwks_uri")
            parsed_jwks = urlsplit(jwks_uri)
            if parsed_jwks.scheme not in {"http", "https"} or not parsed_jwks.hostname:
                raise ValueError("OIDC jwks_uri must be an absolute HTTP(S) URL")
            if (
                parsed_jwks.scheme != "https"
                and parsed_jwks.hostname not in {"127.0.0.1", "localhost", "::1"}
            ):
                raise ValueError("OIDC jwks_uri must use HTTPS")
            if not _same_origin(self._issuer, jwks_uri):
                raise ValueError("OIDC jwks_uri must remain on the configured issuer origin")

            jwks = await self._fetch_json(jwks_uri)
            keys = jwks.get("keys")
            if not isinstance(keys, list) or not keys:
                raise ValueError("OIDC JWKS must contain at least one signing key")
            normalized = [key for key in keys if isinstance(key, dict)]
            if not normalized:
                raise ValueError("OIDC JWKS did not contain a usable signing key")
            self._jwks = normalized
            self._cache_expires = now + _OIDC_CACHE_SECONDS

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token.strip():
            return None
        try:
            header = jwt.get_unverified_header(token)
            algorithm = str(header.get("alg", ""))
            key_id = str(header.get("kid", ""))
            if algorithm not in _OIDC_ALGORITHMS or not key_id:
                return None

            await self._refresh_jwks()
            signing_key = None
            for raw_key in self._jwks:
                if str(raw_key.get("kid", "")) != key_id:
                    continue
                if raw_key.get("use") not in {None, "sig"}:
                    continue
                jwk = jwt.PyJWK.from_dict(raw_key, algorithm=algorithm)
                signing_key = jwk.key
                break
            if signing_key is None:
                # Permit one refresh for normal key rotation, but still fail closed.
                self._cache_expires = 0.0
                await self._refresh_jwks()
                for raw_key in self._jwks:
                    if str(raw_key.get("kid", "")) != key_id:
                        continue
                    if raw_key.get("use") not in {None, "sig"}:
                        continue
                    signing_key = jwt.PyJWK.from_dict(raw_key, algorithm=algorithm).key
                    break
            if signing_key is None:
                return None

            claims = jwt.decode(
                token,
                signing_key,
                algorithms=[algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["aud", "exp", "iss", "sub"]},
            )
            if not isinstance(claims, dict):
                return None

            scopes = _token_scopes(claims)
            if not self._required_scopes.issubset(scopes):
                return None

            subject = str(claims.get("sub", "")).strip()
            if not subject:
                return None
            client_id = str(
                claims.get("azp")
                or claims.get("client_id")
                or claims.get("appid")
                or subject
            ).strip()
            safe_claims: dict[str, Any] = {
                "_flowoox_auth_mode": "oidc",
                "iss": self._issuer,
            }
            for name in ("oid", "preferred_username", "email", "name", "tid"):
                value = claims.get(name)
                if isinstance(value, str) and value.strip():
                    safe_claims[name] = value.strip()
            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=int(claims["exp"]),
                resource=self._resource,
                subject=subject,
                claims=safe_claims,
            )
        except (InvalidTokenError, ValueError, TypeError, KeyError, httpx.HTTPError):
            return None


@dataclass(frozen=True)
class McpServerSecurity:
    transport_security: TransportSecuritySettings
    auth: AuthSettings | None = None
    token_verifier: TokenVerifier | None = None


def build_mcp_server_security(
    settings: Any,
    *,
    service_hosts: Iterable[str],
    required_scopes: Iterable[str] | None = None,
) -> McpServerSecurity:
    """Build an explicit FastMCP transport/auth trust boundary.

    Internal deployments still get DNS-rebinding Host/Origin checks. External
    deployments require either a static bootstrap token or an OAuth/OIDC issuer.
    OIDC mode is selected by leaving MCP_AUTH_TOKEN empty and configuring
    MCP_ISSUER_URL; tokens are then signature/issuer/time/audience/scope checked.
    """

    trust_boundary = str(getattr(settings, "mcp_trust_boundary", "internal")).strip().lower()
    if trust_boundary not in {"internal", "external"}:
        raise ValueError("MCP_TRUST_BOUNDARY must be either 'internal' or 'external'")

    service_hosts = tuple(_csv(service_hosts))
    if required_scopes is None:
        derived_scopes: list[str] = []
        for service_host in service_hosts:
            if service_host == "mcp-exchange-m365":
                derived_scopes.append(
                    "mcp.exchange.manage"
                    if bool(getattr(settings, "exchange_writes_enabled", False))
                    else "mcp.infrastructure.observe"
                )
            else:
                derived_scopes.extend(_SERVICE_SCOPES.get(service_host, ("mcp",)))
        scopes = list(dict.fromkeys(derived_scopes))
    else:
        scopes = list(dict.fromkeys(_csv(required_scopes)))
    if not scopes:
        raise ValueError("MCP required scopes must not be empty")

    allowed_hosts = set(LOCAL_HOSTS)
    for service_host in service_hosts:
        host = str(service_host).strip()
        if host:
            allowed_hosts.add(host)
            allowed_hosts.add(f"{host}:*")
    allowed_hosts.update(_csv(getattr(settings, "mcp_allowed_hosts", "")))

    allowed_origins = set(LOCAL_ORIGINS)
    allowed_origins.update(_csv(getattr(settings, "mcp_allowed_origins", "")))

    public_url = str(getattr(settings, "mcp_public_url", "") or "").strip()
    public_origin = ""
    if public_url:
        scheme, host, port = _origin(public_url)
        public_origin = _origin_text(public_url)
        rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        allowed_hosts.add(rendered_host)
        allowed_hosts.add(f"{rendered_host}:{port}" if port else f"{rendered_host}:*")
        allowed_origins.add(public_origin)
        if trust_boundary == "external" and scheme != "https" and host not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("External MCP_PUBLIC_URL must use https")

    transport = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(allowed_hosts),
        allowed_origins=sorted(allowed_origins),
    )

    if trust_boundary == "internal":
        return McpServerSecurity(transport_security=transport)

    if not public_url:
        raise ValueError("External MCP trust boundary requires MCP_PUBLIC_URL")

    token = str(getattr(settings, "mcp_auth_token", "") or "").strip()
    issuer_setting = str(getattr(settings, "mcp_issuer_url", "") or "").strip()

    if token:
        # Backwards-compatible bootstrap/single-client mode. This is not an
        # employee identity boundary; multi-user administrative deployments use OIDC.
        issuer_url = issuer_setting or public_origin
        auth = AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=public_url,
            required_scopes=scopes,
        )
        return McpServerSecurity(
            transport_security=transport,
            auth=auth,
            token_verifier=StaticBearerTokenVerifier(
                token,
                resource=public_url,
                scopes=scopes,
            ),
        )

    if not issuer_setting:
        raise ValueError(
            "External MCP trust boundary requires MCP_AUTH_TOKEN for bootstrap "
            "or MCP_ISSUER_URL for OAuth/OIDC"
        )
    issuer_url = _issuer_url(issuer_setting)
    audience = str(getattr(settings, "mcp_oidc_audience", "") or "").strip() or public_url
    auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=public_url,
        required_scopes=scopes,
    )
    return McpServerSecurity(
        transport_security=transport,
        auth=auth,
        token_verifier=OidcJwtTokenVerifier(
            issuer=issuer_url,
            audience=audience,
            resource=public_url,
            required_scopes=scopes,
        ),
    )
