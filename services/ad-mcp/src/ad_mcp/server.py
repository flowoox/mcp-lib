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
    Verification,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .baseline import BaselineProfile, evaluate_security_snapshot
from .changes import (
    GroupMembershipRequest,
    PlanRequest,
    UserEnabledRequest,
    authorize_change,
    build_group_membership_plan,
    build_user_enabled_plan,
    change_response,
    group_membership_target,
    user_enabled_target,
    verify_response,
)
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


class ListLimitInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=200, ge=1, le=1000)


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


def _direct_membership(groups: dict[str, Any], group_dn: str) -> bool:
    return any(
        str(item.get("distinguishedName", "")).casefold() == group_dn.casefold()
        for item in groups.get("directGroups", [])
        if isinstance(item, dict)
    )


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
            "Typed Microsoft Active Directory diagnostics and controlled lifecycle operations. "
            "The service executes only repository-owned PowerShell probes, never accepts arbitrary "
            "PowerShell input, and keeps state-changing tools disabled unless an explicit runtime "
            "write boundary and signed out-of-band approval grants are configured."
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

    def require_writes() -> None:
        if not settings.ad_writes_enabled:
            raise PermissionError("AD mutation tools are disabled by AD_WRITES_ENABLED=false")

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the stable AD MCP contract and runtime requirements."""
        return capabilities(writes_enabled=settings.ad_writes_enabled)

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
    async def dns_discovery(correlation_id: str = "") -> dict[str, Any]:
        """Resolve core AD LDAP/Kerberos SRV discovery records through the host resolver."""
        output = await probe(ScriptId.DNS_DISCOVERY)
        return _observe_response("ad.dns.discovery", correlation_id, output)

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
    async def get_user_groups(identity: str, correlation_id: str = "") -> dict[str, Any]:
        """Return direct AD group memberships for one user; nested expansion is intentionally omitted."""
        request = IdentityInput(identity=identity)
        output = await probe(ScriptId.GET_USER_GROUPS, {"identity": request.identity})
        return _observe_response(
            "ad.user.groups", correlation_id, output, target=f"user:{request.identity}"
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

    @mcp.tool()
    async def list_organizational_units(
        limit: int = 200, correlation_id: str = ""
    ) -> dict[str, Any]:
        """Return a bounded OU inventory sorted by distinguished name."""
        request = ListLimitInput(limit=limit)
        output = await probe(ScriptId.LIST_OUS, {"limit": request.limit})
        return _observe_response("ad.ou.list", correlation_id, output)

    @mcp.tool()
    async def plan_user_enabled(
        identity: str,
        enabled: bool,
        idempotency_key: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Plan an approved enable/disable mutation and capture current AD pre-state."""
        identity_request = IdentityInput(identity=identity)
        plan_request = PlanRequest(idempotency_key=idempotency_key)
        current = await probe(ScriptId.GET_USER, {"identity": identity_request.identity})
        return build_user_enabled_plan(
            identity=identity_request.identity,
            enabled=enabled,
            current=current,
            correlation_id=correlation_id,
            idempotency_key=plan_request.idempotency_key,
        )

    @mcp.tool()
    async def change_user_enabled(
        identity: str,
        enabled: bool,
        idempotency_key: str,
        approval_grant: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Enable/disable one user only after verifying an exact signed approval grant."""
        require_writes()
        request = UserEnabledRequest(
            identity=identity,
            enabled=enabled,
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        target = user_enabled_target(request.identity)
        approval = authorize_change(
            grant=request.approval_grant,
            secret=settings.ad_approval_secret,
            operation="ad.user.enabled.change",
            target=target,
            idempotency_key=request.idempotency_key,
        )
        output = await probe(
            ScriptId.SET_USER_ENABLED,
            {"identity": request.identity, "enabled": request.enabled},
        )
        observed = await probe(ScriptId.GET_USER, {"identity": request.identity})
        passed = bool(observed.get("enabled")) == request.enabled
        verification = Verification(
            check="independent user enabled-state readback",
            passed=passed,
            details={"expectedEnabled": request.enabled, "observedEnabled": observed.get("enabled")},
        )
        return change_response(
            operation="ad.user.enabled.change",
            target=target,
            correlation_id=correlation_id,
            idempotency_key=request.idempotency_key,
            changed=bool(output.get("changed")),
            output=output,
            approval=approval,
            verification=verification,
        )

    @mcp.tool()
    async def verify_user_enabled(
        identity: str,
        enabled: bool,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Independently verify the current enabled state for one user."""
        request = IdentityInput(identity=identity)
        observed = await probe(ScriptId.GET_USER, {"identity": request.identity})
        actual = bool(observed.get("enabled"))
        return verify_response(
            operation="ad.user.enabled.verify",
            target=user_enabled_target(request.identity),
            correlation_id=correlation_id,
            check="user enabled-state equals requested state",
            passed=actual == enabled,
            details={"expectedEnabled": enabled, "observedEnabled": actual},
        )

    @mcp.tool()
    async def plan_user_group_membership(
        user_identity: str,
        group_identity: str,
        present: bool,
        idempotency_key: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Plan a direct user/group membership mutation and capture its current state."""
        user = IdentityInput(identity=user_identity)
        group = IdentityInput(identity=group_identity)
        plan_request = PlanRequest(idempotency_key=idempotency_key)
        group_object = await probe(ScriptId.GET_GROUP, {"identity": group.identity})
        groups = await probe(ScriptId.GET_USER_GROUPS, {"identity": user.identity})
        current_present = _direct_membership(groups, str(group_object["distinguishedName"]))
        return build_group_membership_plan(
            user_identity=user.identity,
            group_identity=group.identity,
            present=present,
            current_present=current_present,
            correlation_id=correlation_id,
            idempotency_key=plan_request.idempotency_key,
        )

    @mcp.tool()
    async def change_user_group_membership(
        user_identity: str,
        group_identity: str,
        present: bool,
        idempotency_key: str,
        approval_grant: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Add/remove one direct group membership after exact signed approval verification."""
        require_writes()
        request = GroupMembershipRequest(
            user_identity=user_identity,
            group_identity=group_identity,
            present=present,
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        target = group_membership_target(request.user_identity, request.group_identity)
        approval = authorize_change(
            grant=request.approval_grant,
            secret=settings.ad_approval_secret,
            operation="ad.user.group-membership.change",
            target=target,
            idempotency_key=request.idempotency_key,
        )
        output = await probe(
            ScriptId.SET_USER_GROUP_MEMBERSHIP,
            {
                "userIdentity": request.user_identity,
                "groupIdentity": request.group_identity,
                "present": request.present,
            },
        )
        group_object = await probe(ScriptId.GET_GROUP, {"identity": request.group_identity})
        groups = await probe(ScriptId.GET_USER_GROUPS, {"identity": request.user_identity})
        observed_present = _direct_membership(groups, str(group_object["distinguishedName"]))
        verification = Verification(
            check="independent direct group-membership readback",
            passed=observed_present == request.present,
            details={
                "expectedPresent": request.present,
                "observedPresent": observed_present,
                "groupObjectGuid": group_object.get("objectGuid"),
            },
        )
        return change_response(
            operation="ad.user.group-membership.change",
            target=target,
            correlation_id=correlation_id,
            idempotency_key=request.idempotency_key,
            changed=bool(output.get("changed")),
            output=output,
            approval=approval,
            verification=verification,
        )

    @mcp.tool()
    async def verify_user_group_membership(
        user_identity: str,
        group_identity: str,
        present: bool,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Independently verify one direct user/group membership state."""
        user = IdentityInput(identity=user_identity)
        group = IdentityInput(identity=group_identity)
        group_object = await probe(ScriptId.GET_GROUP, {"identity": group.identity})
        groups = await probe(ScriptId.GET_USER_GROUPS, {"identity": user.identity})
        actual = _direct_membership(groups, str(group_object["distinguishedName"]))
        return verify_response(
            operation="ad.user.group-membership.verify",
            target=group_membership_target(user.identity, group.identity),
            correlation_id=correlation_id,
            check="direct group membership equals requested state",
            passed=actual == present,
            details={"expectedPresent": present, "observedPresent": actual},
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
