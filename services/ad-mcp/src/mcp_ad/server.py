from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, TypeVar
from uuid import UUID, uuid4

from mcp.server.fastmcp import FastMCP

from mcp_common.mcp_security import build_mcp_server_security

from .audit import run_security_audit
from .audit_log import emit_audit_event
from .client import DirectoryConnectionError, DirectoryQueryError, LdapDirectoryClient
from .contract import CAPABILITIES
from .settings import Settings

T = TypeVar("T")


def _request_id(value: str | None) -> UUID:
    if value is None or not value.strip():
        return uuid4()
    try:
        return UUID(value.strip())
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc


def _request_metadata(actor: str, source: str, reason: str) -> tuple[str, str, str]:
    normalized_actor = actor.strip()
    normalized_source = source.strip()
    normalized_reason = reason.strip()
    if not normalized_actor or len(normalized_actor) > 200:
        raise ValueError("actor must contain 1-200 characters")
    if not normalized_source or len(normalized_source) > 100:
        raise ValueError("source must contain 1-100 characters")
    if not normalized_reason or len(normalized_reason) > 1000:
        raise ValueError("reason must contain 1-1000 characters")
    return normalized_actor, normalized_source, normalized_reason


async def _observe(
    *,
    operation: str,
    actor: str,
    source: str,
    reason: str,
    correlation_id: str | None,
    call: Callable[[], T],
) -> dict[str, Any]:
    request_id = _request_id(correlation_id)
    normalized_actor, normalized_source, normalized_reason = _request_metadata(
        actor, source, reason
    )
    base_event = {
        "operation": operation,
        "phase": "observe",
        "risk": "read_only",
        "correlation_id": str(request_id),
        "actor": normalized_actor,
        "source": normalized_source,
        "reason": normalized_reason,
        "changed": False,
    }
    try:
        result = await asyncio.to_thread(call)
    except (ValueError, PermissionError, DirectoryConnectionError, DirectoryQueryError) as exc:
        emit_audit_event({**base_event, "status": "failed", "error_type": type(exc).__name__})
        raise RuntimeError(str(exc)) from exc
    except Exception as exc:
        emit_audit_event({**base_event, "status": "failed", "error_type": type(exc).__name__})
        raise RuntimeError(f"{operation} failed") from exc

    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    emit_audit_event({**base_event, "status": "succeeded"})
    return {"correlation_id": str(request_id), "result": payload}


def build_server(settings: Settings) -> FastMCP:
    client = LdapDirectoryClient(settings)
    security_input = SimpleNamespace(
        mcp_trust_boundary=settings.mcp_trust_boundary,
        mcp_allowed_hosts=settings.mcp_allowed_hosts,
        mcp_allowed_origins=settings.mcp_allowed_origins,
        mcp_public_url=settings.mcp_public_url,
        mcp_auth_token=settings.auth_token,
        mcp_issuer_url=settings.mcp_issuer_url,
    )
    security = build_mcp_server_security(
        security_input,
        service_hosts=(settings.mcp_host, "ad-mcp", "mcp-ad"),
    )
    mcp = FastMCP(
        "Active Directory MCP",
        host=settings.mcp_host,
        port=settings.mcp_port,
        streamable_http_path="/mcp",
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the versioned contract and explicit safety constraints."""

        return CAPABILITIES

    @mcp.tool()
    async def ad_observe_domain_policy(
        actor: str,
        reason: str,
        source: str = "mcp-client",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Read effective domain-root password and lockout policy attributes."""

        return await _observe(
            operation="ad_observe_domain_policy",
            actor=actor,
            source=source,
            reason=reason,
            correlation_id=correlation_id,
            call=client.get_domain_policy,
        )

    @mcp.tool()
    async def ad_find_user(
        identifier: str,
        actor: str,
        reason: str,
        source: str = "mcp-client",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Find a user by exact account name, UPN or mail address."""

        return await _observe(
            operation="ad_find_user",
            actor=actor,
            source=source,
            reason=reason,
            correlation_id=correlation_id,
            call=lambda: client.find_user(identifier),
        )

    @mcp.tool()
    async def ad_get_group_members(
        group_dn: str,
        actor: str,
        reason: str,
        limit: int | None = None,
        source: str = "mcp-client",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """List direct members of an allowlisted group DN with bounded output."""

        if limit is not None and (limit < 1 or limit > settings.ad_max_results):
            raise ValueError(f"limit must be between 1 and {settings.ad_max_results}")
        return await _observe(
            operation="ad_get_group_members",
            actor=actor,
            source=source,
            reason=reason,
            correlation_id=correlation_id,
            call=lambda: client.get_group_members(group_dn, limit=limit),
        )

    @mcp.tool()
    async def ad_list_domain_controllers(
        actor: str,
        reason: str,
        source: str = "mcp-client",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """List domain-controller computer objects and bounded metadata."""

        return await _observe(
            operation="ad_list_domain_controllers",
            actor=actor,
            source=source,
            reason=reason,
            correlation_id=correlation_id,
            call=client.list_domain_controllers,
        )

    @mcp.tool()
    async def ad_run_security_audit(
        actor: str,
        reason: str,
        source: str = "mcp-client",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Run deterministic read-only checks against the configured AD scope."""

        return await _observe(
            operation="ad_run_security_audit",
            actor=actor,
            source=source,
            reason=reason,
            correlation_id=correlation_id,
            call=lambda: run_security_audit(client),
        )

    return mcp


def main() -> None:
    settings = Settings()
    server = build_server(settings)
    server.run(transport=settings.mcp_transport)


if __name__ == "__main__":
    main()
