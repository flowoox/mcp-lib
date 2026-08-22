from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.operations import (
    AuditEvent,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .baseline import BaselineProfile, evaluate_security_snapshot
from .config import get_settings
from .contract import capabilities
from .runner import PowerShellRunner
from .scripts import ScriptId


class IdentityInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: str = Field(min_length=1, max_length=512)

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("identity must not be blank")
        if any(ord(character) < 32 for character in value):
            raise ValueError("identity must not contain control characters")
        return value


def _context(correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor="mcp-client", source="ad-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor="mcp-client", source="ad-mcp")


def _observe_response(
    operation: str,
    correlation_id: str,
    output: dict[str, Any],
    *,
    target: str | None = None,
) -> dict[str, Any]:
    context = _context(correlation_id)
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        status=OperationStatus.SUCCEEDED,
        context=context,
        output=output,
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=target,
        status=OperationStatus.SUCCEEDED,
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


def create_server() -> FastMCP:
    settings = get_settings()
    runner = PowerShellRunner(
        settings.ad_powershell_executable,
        timeout_seconds=settings.ad_command_timeout_seconds,
    )
    security = build_mcp_server_security(settings, service_hosts=("mcp-ad",))
    mcp = FastMCP(
        "Flowoox Active Directory MCP",
        instructions=(
            "Read-only, typed Microsoft Active Directory diagnostics. The service executes only "
            "repository-owned PowerShell probes and never accepts arbitrary PowerShell input."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    async def probe(script_id: ScriptId, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return await asyncio.to_thread(runner.run, script_id, payload)

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the stable AD MCP contract and runtime requirements."""
        return capabilities()

    @mcp.tool()
    async def domain_summary(correlation_id: str = "") -> dict[str, Any]:
        """Return forest, domain, FSMO and domain-controller inventory without changing AD."""
        output = await probe(ScriptId.DOMAIN_SUMMARY)
        return _observe_response("ad.domain.summary", correlation_id, output)

    @mcp.tool()
    async def replication_health(correlation_id: str = "") -> dict[str, Any]:
        """Return forest replication failures and partner metadata without repair actions."""
        output = await probe(ScriptId.REPLICATION_HEALTH)
        return _observe_response("ad.replication.health", correlation_id, output)

    @mcp.tool()
    async def local_secure_channel(correlation_id: str = "") -> dict[str, Any]:
        """Test this Windows member's domain secure channel; never invokes repair."""
        output = await probe(ScriptId.LOCAL_SECURE_CHANNEL)
        return _observe_response("ad.secure-channel.local", correlation_id, output)

    @mcp.tool()
    async def security_baseline(
        correlation_id: str = "",
        minimum_password_length: int = 14,
        minimum_password_history: int = 24,
        maximum_lockout_threshold: int = 10,
        maximum_machine_account_quota: int = 0,
    ) -> dict[str, Any]:
        """Evaluate read-only AD policy evidence against caller-selected baseline thresholds."""
        profile = BaselineProfile(
            minimum_password_length=minimum_password_length,
            minimum_password_history=minimum_password_history,
            maximum_lockout_threshold=maximum_lockout_threshold,
            maximum_machine_account_quota=maximum_machine_account_quota,
        )
        raw = await probe(ScriptId.SECURITY_SNAPSHOT)
        report = evaluate_security_snapshot(raw, profile)
        return _observe_response(
            "ad.security.baseline", correlation_id, report.model_dump(mode="json")
        )

    @mcp.tool()
    async def get_user(identity: str, correlation_id: str = "") -> dict[str, Any]:
        """Return bounded, non-secret properties for one user identified by AD -Identity."""
        request = IdentityInput(identity=identity)
        output = await probe(ScriptId.GET_USER, {"identity": request.identity})
        return _observe_response(
            "ad.user.get", correlation_id, output, target=f"user:{request.identity}"
        )

    @mcp.tool()
    async def get_computer(identity: str, correlation_id: str = "") -> dict[str, Any]:
        """Return bounded properties for one computer identified by AD -Identity."""
        request = IdentityInput(identity=identity)
        output = await probe(ScriptId.GET_COMPUTER, {"identity": request.identity})
        return _observe_response(
            "ad.computer.get", correlation_id, output, target=f"computer:{request.identity}"
        )

    @mcp.tool()
    async def get_group(identity: str, correlation_id: str = "") -> dict[str, Any]:
        """Return bounded properties for one group identified by AD -Identity."""
        request = IdentityInput(identity=identity)
        output = await probe(ScriptId.GET_GROUP, {"identity": request.identity})
        return _observe_response(
            "ad.group.get", correlation_id, output, target=f"group:{request.identity}"
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
