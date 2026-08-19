from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from secrets import compare_digest
from typing import Any
from urllib.parse import urlsplit

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


class StaticBearerTokenVerifier(TokenVerifier):
    """Minimal verifier for an operator-provisioned MCP bearer token.

    This is intentionally only a resource-server credential. It does not mint,
    rotate, log, or return the configured token.
    """

    def __init__(self, token: str, *, resource: str):
        if not token.strip():
            raise ValueError("MCP_AUTH_TOKEN must not be empty")
        self._token = token.strip()
        self._resource = resource

    async def verify_token(self, token: str) -> AccessToken | None:
        if not compare_digest(token, self._token):
            return None
        return AccessToken(
            token=token,
            client_id="configured-mcp-client",
            scopes=["mcp"],
            resource=self._resource,
        )


@dataclass(frozen=True)
class McpServerSecurity:
    transport_security: TransportSecuritySettings
    auth: AuthSettings | None = None
    token_verifier: TokenVerifier | None = None


def build_mcp_server_security(
    settings: Any,
    *,
    service_hosts: Iterable[str],
) -> McpServerSecurity:
    """Build an explicit FastMCP transport/auth trust boundary.

    Internal deployments still get DNS-rebinding Host/Origin checks. Switching
    ``MCP_TRUST_BOUNDARY`` to ``external`` is fail-closed unless a public URL and
    bearer token are explicitly configured.
    """

    trust_boundary = str(getattr(settings, "mcp_trust_boundary", "internal")).strip().lower()
    if trust_boundary not in {"internal", "external"}:
        raise ValueError("MCP_TRUST_BOUNDARY must be either 'internal' or 'external'")

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
    if not token:
        raise ValueError("External MCP trust boundary requires MCP_AUTH_TOKEN")

    issuer_url = str(getattr(settings, "mcp_issuer_url", "") or "").strip() or public_origin
    auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=public_url,
        required_scopes=["mcp"],
    )
    return McpServerSecurity(
        transport_security=transport,
        auth=auth,
        token_verifier=StaticBearerTokenVerifier(token, resource=public_url),
    )
