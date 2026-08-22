from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from .changes import authorize_change, change_response, verify_response
from .config import Settings
from .provisioning import (
    DisabledUserChangeRequest,
    DisabledUserFields,
    DisabledUserPlanRequest,
    build_disabled_user_plan,
    disabled_user_target,
    provisioning_verification,
)
from .provisioning_scripts import ProvisioningScriptId
from .runner import PowerShellRunner


def _field_kwargs(
    *,
    name: str,
    sam_account_name: str,
    user_principal_name: str,
    display_name: str,
    ou_dn: str,
    given_name: str | None,
    surname: str | None,
    mail: str | None,
    employee_id: str | None,
    description: str | None,
) -> dict[str, Any]:
    return {
        "name": name,
        "sam_account_name": sam_account_name,
        "user_principal_name": user_principal_name,
        "display_name": display_name,
        "ou_dn": ou_dn,
        "given_name": given_name,
        "surname": surname,
        "mail": mail,
        "employee_id": employee_id,
        "description": description,
    }


def register_provisioning_tools(
    mcp: FastMCP,
    *,
    runner: PowerShellRunner,
    settings: Settings,
) -> None:
    """Register the narrow employee-entry provisioning slice on an AD MCP server."""

    async def probe(
        script_id: ProvisioningScriptId, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return await asyncio.to_thread(runner.run, script_id, payload)

    def require_writes() -> None:
        if not settings.ad_writes_enabled:
            raise PermissionError("AD mutation tools are disabled by AD_WRITES_ENABLED=false")

    @mcp.tool()
    async def plan_user_provision_disabled(
        name: str,
        sam_account_name: str,
        user_principal_name: str,
        display_name: str,
        ou_dn: str,
        idempotency_key: str,
        correlation_id: str = "",
        given_name: str | None = None,
        surname: str | None = None,
        mail: str | None = None,
        employee_id: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Plan creation of one disabled AD user after collision and OU preflight checks."""
        request = DisabledUserPlanRequest(
            **_field_kwargs(
                name=name,
                sam_account_name=sam_account_name,
                user_principal_name=user_principal_name,
                display_name=display_name,
                ou_dn=ou_dn,
                given_name=given_name,
                surname=surname,
                mail=mail,
                employee_id=employee_id,
                description=description,
            ),
            idempotency_key=idempotency_key,
        )
        preflight = await probe(
            ProvisioningScriptId.PREFLIGHT_CREATE_DISABLED_USER,
            request.directory_payload(),
        )
        return build_disabled_user_plan(
            request=request,
            preflight=preflight,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def change_user_provision_disabled(
        name: str,
        sam_account_name: str,
        user_principal_name: str,
        display_name: str,
        ou_dn: str,
        idempotency_key: str,
        approval_grant: str,
        correlation_id: str = "",
        given_name: str | None = None,
        surname: str | None = None,
        mail: str | None = None,
        employee_id: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Create one disabled AD user only after exact signed approval verification."""
        require_writes()
        request = DisabledUserChangeRequest(
            **_field_kwargs(
                name=name,
                sam_account_name=sam_account_name,
                user_principal_name=user_principal_name,
                display_name=display_name,
                ou_dn=ou_dn,
                given_name=given_name,
                surname=surname,
                mail=mail,
                employee_id=employee_id,
                description=description,
            ),
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        target = disabled_user_target(request.sam_account_name)
        approval = authorize_change(
            grant=request.approval_grant,
            secret=settings.ad_approval_secret,
            operation="ad.user.provision-disabled.change",
            target=target,
            idempotency_key=request.idempotency_key,
            intent=request.approval_intent(),
        )
        output = await probe(
            ProvisioningScriptId.CREATE_DISABLED_USER,
            request.directory_payload(),
        )
        readback = await probe(
            ProvisioningScriptId.PREFLIGHT_CREATE_DISABLED_USER,
            request.directory_payload(),
        )
        verification = provisioning_verification(preflight=readback, request=request)
        return change_response(
            operation="ad.user.provision-disabled.change",
            target=target,
            correlation_id=correlation_id,
            idempotency_key=request.idempotency_key,
            changed=bool(output.get("changed")),
            output=output,
            approval=approval,
            verification=verification,
        )

    @mcp.tool()
    async def verify_user_provision_disabled(
        name: str,
        sam_account_name: str,
        user_principal_name: str,
        display_name: str,
        ou_dn: str,
        correlation_id: str = "",
        given_name: str | None = None,
        surname: str | None = None,
        mail: str | None = None,
        employee_id: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Independently verify one disabled AD user against an expected attribute set."""
        request = DisabledUserFields(
            **_field_kwargs(
                name=name,
                sam_account_name=sam_account_name,
                user_principal_name=user_principal_name,
                display_name=display_name,
                ou_dn=ou_dn,
                given_name=given_name,
                surname=surname,
                mail=mail,
                employee_id=employee_id,
                description=description,
            )
        )
        readback = await probe(
            ProvisioningScriptId.PREFLIGHT_CREATE_DISABLED_USER,
            request.directory_payload(),
        )
        verification = provisioning_verification(preflight=readback, request=request)
        return verify_response(
            operation="ad.user.provision-disabled.verify",
            target=disabled_user_target(request.sam_account_name),
            correlation_id=correlation_id,
            check=verification.check,
            passed=verification.passed,
            details=verification.details,
        )
