from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp_common.approval_grants import verify_approval_grant
from mcp_common.operations import (
    Approval,
    ApprovalState,
    AuditEvent,
    ChangePlan,
    ChangeStep,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
    Verification,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import Settings

_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SMTP_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$"
)


class ExchangeManagementError(RuntimeError):
    """Raised when the bounded Exchange Online management adapter fails closed."""


class SharedMailboxPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=256)
    alias: str = Field(min_length=1, max_length=64)
    primary_smtp_address: str = Field(min_length=3, max_length=320)
    idempotency_key: str = Field(min_length=8, max_length=128)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("display_name must not be blank or contain control characters")
        return value

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        value = value.strip()
        if not _ALIAS_RE.fullmatch(value):
            raise ValueError("alias contains unsupported characters")
        return value.lower()

    @field_validator("primary_smtp_address")
    @classmethod
    def validate_primary_smtp_address(cls, value: str) -> str:
        value = value.strip().lower()
        if not _SMTP_RE.fullmatch(value):
            raise ValueError("primary_smtp_address must be a bounded SMTP address")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        context = OperationContext(
            actor="validation",
            source="exchange-m365-mcp",
            idempotency_key=value,
        )
        if context.idempotency_key is None:  # pragma: no cover
            raise ValueError("idempotency_key is required")
        return context.idempotency_key


class SharedMailboxChangeRequest(SharedMailboxPlanRequest):
    approval_grant: str = Field(min_length=16, max_length=8192)


def _correlation_context(
    *,
    actor: str,
    correlation_id: str,
    idempotency_key: str | None = None,
) -> OperationContext:
    kwargs: dict[str, Any] = {
        "actor": actor.strip(),
        "source": "exchange-m365-mcp",
        "idempotency_key": idempotency_key,
    }
    value = correlation_id.strip()
    if value:
        try:
            kwargs["correlation_id"] = UUID(value)
        except ValueError as exc:
            raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(**kwargs)


def _reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 1000:
        raise ValueError("reason must contain 1-1000 characters")
    return value


def _target(address: str) -> str:
    return f"mailbox:{address.strip().lower()}"


def _intent(request: SharedMailboxPlanRequest) -> dict[str, Any]:
    return {
        "mailboxType": "shared",
        "displayName": request.display_name,
        "alias": request.alias,
        "primarySmtpAddress": request.primary_smtp_address,
    }


def _allowed_domains(settings: Settings) -> set[str]:
    return {
        item.strip().lower().rstrip(".")
        for item in settings.exchange_mailbox_allowed_domains.split(",")
        if item.strip()
    }


def _validate_allowed_domain(settings: Settings, address: str) -> None:
    domain = address.rsplit("@", 1)[1].lower().rstrip(".")
    if domain not in _allowed_domains(settings):
        raise PermissionError("mailbox domain is not included in EXCHANGE_MAILBOX_ALLOWED_DOMAINS")


_SCRIPT_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
""".strip()

_SCRIPT_CONNECT = r"""
Connect-ExchangeOnline `
    -AppId $env:MCP_EXCHANGE_MANAGEMENT_APP_ID `
    -CertificateThumbprint $env:MCP_EXCHANGE_MANAGEMENT_CERT_THUMBPRINT `
    -Organization $env:MCP_EXCHANGE_ORGANIZATION `
    -CommandName $commands `
    -ShowBanner:$false
""".strip()

_SCRIPT_FINALLY = r"""
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
""".strip()


class ExchangeOnlineMailboxManagementTransport:
    """Fixed Exchange Online shared-mailbox lifecycle adapter."""

    def __init__(self, settings: Settings) -> None:
        if not settings.exchange_writes_enabled:
            raise PermissionError("Exchange mailbox writes are disabled")
        settings.validate_write_boundary()
        self.settings = settings

    async def _invoke(
        self,
        *,
        commands: tuple[str, ...],
        body: str,
        environment: Mapping[str, str],
    ) -> Any:
        command_literal = "@(" + ",".join(f"'{command}'" for command in commands) + ")"
        script = "\n".join(
            (
                _SCRIPT_PREAMBLE,
                f"$commands = {command_literal}",
                "try {",
                _SCRIPT_CONNECT,
                body,
                _SCRIPT_FINALLY,
            )
        )
        env = os.environ.copy()
        env.update(
            {
                "MCP_EXCHANGE_MANAGEMENT_APP_ID": self.settings.exchange_management_app_id,
                "MCP_EXCHANGE_MANAGEMENT_CERT_THUMBPRINT": self.settings.exchange_management_certificate_thumbprint,
                "MCP_EXCHANGE_ORGANIZATION": self.settings.exchange_organization,
            }
        )
        env.update({key: str(value) for key, value in environment.items()})
        process = await asyncio.create_subprocess_exec(
            self.settings.exchange_powershell_executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.settings.exchange_request_timeout_seconds,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > self.settings.exchange_max_response_bytes:
            raise ExchangeManagementError("Exchange management response exceeded the byte limit")
        if process.returncode != 0:
            detail = " (backend returned a redacted error)" if stderr else ""
            raise ExchangeManagementError(f"Exchange management command failed{detail}")
        if not stdout.strip():
            return None
        try:
            return json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExchangeManagementError("Exchange management command returned invalid JSON") from exc

    async def get_mailbox(self, address: str) -> dict[str, Any] | None:
        payload = await self._invoke(
            commands=("Get-Mailbox",),
            environment={"MCP_EXCHANGE_TARGET_ADDRESS": address},
            body=r"""
$mailbox = Get-Mailbox -Identity $env:MCP_EXCHANGE_TARGET_ADDRESS -ErrorAction SilentlyContinue
if ($null -eq $mailbox) {
    'null'
} else {
    $mailbox | Select-Object DisplayName,Alias,@{n='PrimarySmtpAddress';e={$_.PrimarySmtpAddress.ToString()}},RecipientTypeDetails,ExternalDirectoryObjectId | ConvertTo-Json -Depth 3 -Compress
}
""".strip(),
        )
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise ExchangeManagementError("Exchange returned an invalid mailbox object")
        return {str(key): value for key, value in payload.items()}

    async def create_shared_mailbox(
        self,
        request: SharedMailboxPlanRequest,
    ) -> dict[str, Any]:
        payload = await self._invoke(
            commands=("Get-Mailbox", "New-Mailbox"),
            environment={
                "MCP_EXCHANGE_TARGET_ADDRESS": request.primary_smtp_address,
                "MCP_EXCHANGE_TARGET_ALIAS": request.alias,
                "MCP_EXCHANGE_TARGET_DISPLAY_NAME": request.display_name,
            },
            body=r"""
$mailbox = Get-Mailbox -Identity $env:MCP_EXCHANGE_TARGET_ADDRESS -ErrorAction SilentlyContinue
$changed = $false
if ($null -eq $mailbox) {
    New-Mailbox `
        -Shared `
        -Name $env:MCP_EXCHANGE_TARGET_DISPLAY_NAME `
        -DisplayName $env:MCP_EXCHANGE_TARGET_DISPLAY_NAME `
        -Alias $env:MCP_EXCHANGE_TARGET_ALIAS `
        -PrimarySmtpAddress $env:MCP_EXCHANGE_TARGET_ADDRESS `
        -Confirm:$false | Out-Null
    $changed = $true
    $mailbox = Get-Mailbox -Identity $env:MCP_EXCHANGE_TARGET_ADDRESS -ErrorAction Stop
}
[pscustomobject]@{
    changed = $changed
    mailbox = [pscustomobject]@{
        DisplayName = $mailbox.DisplayName
        Alias = $mailbox.Alias
        PrimarySmtpAddress = $mailbox.PrimarySmtpAddress.ToString()
        RecipientTypeDetails = $mailbox.RecipientTypeDetails.ToString()
        ExternalDirectoryObjectId = $mailbox.ExternalDirectoryObjectId
    }
} | ConvertTo-Json -Depth 4 -Compress
""".strip(),
        )
        if not isinstance(payload, Mapping) or not isinstance(payload.get("mailbox"), Mapping):
            raise ExchangeManagementError("Exchange returned an invalid create result")
        return {
            "changed": bool(payload.get("changed")),
            "mailbox": {str(key): value for key, value in payload["mailbox"].items()},
        }


def _state_matches(request: SharedMailboxPlanRequest, mailbox: Mapping[str, Any]) -> bool:
    return (
        str(mailbox.get("RecipientTypeDetails", "")).casefold() == "sharedmailbox"
        and str(mailbox.get("PrimarySmtpAddress", "")).casefold()
        == request.primary_smtp_address.casefold()
        and str(mailbox.get("Alias", "")).casefold() == request.alias.casefold()
        and str(mailbox.get("DisplayName", "")) == request.display_name
    )


def _plan_payload(
    *,
    request: SharedMailboxPlanRequest,
    current: Mapping[str, Any] | None,
    actor: str,
    reason: str,
    correlation_id: str,
) -> dict[str, Any]:
    context = _correlation_context(
        actor=actor,
        correlation_id=correlation_id,
        idempotency_key=request.idempotency_key,
    )
    target = _target(request.primary_smtp_address)
    if current is not None and not _state_matches(request, current):
        raise ValueError("a recipient already exists at the requested address with different state")
    already_satisfied = current is not None
    plan = ChangePlan(
        operation="exchange.mailbox.shared.create.change",
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="ensure-shared-mailbox",
                target=target,
                reversible=False,
            )
        ],
        pre_state={
            "exists": current is not None,
            "recipientTypeDetails": (
                str(current.get("RecipientTypeDetails", "")) if current is not None else None
            ),
        },
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason="Creating a cloud mailbox changes tenant recipient state and requires approval.",
        ),
    )
    audit = AuditEvent(
        operation="exchange.mailbox.shared.create.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={"reason": _reason(reason), "alreadySatisfied": already_satisfied},
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "approvalBinding": {
            "operation": "exchange.mailbox.shared.create.change",
            "target": target,
            "idempotencyKey": context.idempotency_key,
            "intent": _intent(request),
        },
        "alreadySatisfied": already_satisfied,
        "audit": audit.model_dump(mode="json"),
    }


def _verification(
    request: SharedMailboxPlanRequest,
    mailbox: Mapping[str, Any] | None,
) -> Verification:
    return Verification(
        check="shared mailbox exact desired state",
        passed=mailbox is not None and _state_matches(request, mailbox),
        details={
            "exists": mailbox is not None,
            "recipientTypeDetails": (
                str(mailbox.get("RecipientTypeDetails", "")) if mailbox is not None else None
            ),
        },
    )


def register_mailbox_management_tools(mcp: FastMCP, settings: Settings) -> None:
    """Register high-risk mailbox management tools only when explicitly enabled."""
    if not settings.exchange_writes_enabled:
        return

    settings.validate_write_boundary()
    transport = ExchangeOnlineMailboxManagementTransport(settings)

    @mcp.tool()
    async def exchange_plan_shared_mailbox_create(
        display_name: str,
        alias: str,
        primary_smtp_address: str,
        idempotency_key: str,
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        request = SharedMailboxPlanRequest(
            display_name=display_name,
            alias=alias,
            primary_smtp_address=primary_smtp_address,
            idempotency_key=idempotency_key,
        )
        _validate_allowed_domain(settings, request.primary_smtp_address)
        current = await transport.get_mailbox(request.primary_smtp_address)
        return _plan_payload(
            request=request,
            current=current,
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
        )

    @mcp.tool()
    async def exchange_create_shared_mailbox(
        display_name: str,
        alias: str,
        primary_smtp_address: str,
        idempotency_key: str,
        approval_grant: str,
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        request = SharedMailboxChangeRequest(
            display_name=display_name,
            alias=alias,
            primary_smtp_address=primary_smtp_address,
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        _validate_allowed_domain(settings, request.primary_smtp_address)
        target = _target(request.primary_smtp_address)
        approval = verify_approval_grant(
            request.approval_grant,
            settings.exchange_approval_secret,
            operation="exchange.mailbox.shared.create.change",
            target=target,
            idempotency_key=request.idempotency_key,
            intent=_intent(request),
        )
        before = await transport.get_mailbox(request.primary_smtp_address)
        if before is not None and not _state_matches(request, before):
            raise ValueError("a recipient already exists at the requested address with different state")
        result = await transport.create_shared_mailbox(request)
        after = result["mailbox"]
        verification = _verification(request, after)
        context = _correlation_context(
            actor=actor,
            correlation_id=correlation_id,
            idempotency_key=request.idempotency_key,
        )
        status = OperationStatus.SUCCEEDED if verification.passed else OperationStatus.FAILED
        operation_result = OperationResult(
            operation="exchange.mailbox.shared.create.change",
            phase=OperationPhase.CHANGE,
            status=status,
            context=context,
            changed=bool(result["changed"]),
            output={
                "mailboxType": "shared",
                "primarySmtpAddress": request.primary_smtp_address,
                "alreadyExisted": before is not None,
            },
            verification=[verification],
        )
        audit = AuditEvent(
            operation="exchange.mailbox.shared.create.change",
            phase=OperationPhase.CHANGE,
            risk=RiskLevel.HIGH,
            context=context,
            target=target,
            status=status,
            changed=bool(result["changed"]),
            metadata={
                "reason": _reason(reason),
                "approvalState": approval.state.value,
                "approver": approval.approver,
                "verificationPassed": verification.passed,
            },
        )
        payload = operation_result.model_dump(mode="json")
        payload["audit"] = audit.model_dump(mode="json")
        return payload

    @mcp.tool()
    async def exchange_verify_shared_mailbox(
        display_name: str,
        alias: str,
        primary_smtp_address: str,
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        request = SharedMailboxPlanRequest(
            display_name=display_name,
            alias=alias,
            primary_smtp_address=primary_smtp_address,
            idempotency_key="verify-only",
        )
        _validate_allowed_domain(settings, request.primary_smtp_address)
        mailbox = await transport.get_mailbox(request.primary_smtp_address)
        verification = _verification(request, mailbox)
        context = _correlation_context(actor=actor, correlation_id=correlation_id)
        status = OperationStatus.SUCCEEDED if verification.passed else OperationStatus.FAILED
        result = OperationResult(
            operation="exchange.mailbox.shared.create.verify",
            phase=OperationPhase.VERIFY,
            status=status,
            context=context,
            verification=[verification],
            output={
                "mailboxType": "shared",
                "primarySmtpAddress": request.primary_smtp_address,
            },
        )
        audit = AuditEvent(
            operation="exchange.mailbox.shared.create.verify",
            phase=OperationPhase.VERIFY,
            risk=RiskLevel.READ_ONLY,
            context=context,
            target=_target(request.primary_smtp_address),
            status=status,
            metadata={"reason": _reason(reason)},
        )
        payload = result.model_dump(mode="json")
        payload["audit"] = audit.model_dump(mode="json")
        return payload
