from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp_common.operations import (
    AuditEvent,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
)

from .config import Settings

_SMTP_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$"
)


class ExchangeMailboxDebugError(RuntimeError):
    """Raised when the bounded Exchange mailbox diagnostic adapter fails closed."""


def _mailbox_ref(address: str) -> str:
    digest = hashlib.sha256(address.strip().lower().encode("utf-8")).hexdigest()[:16]
    return f"mailbox:{digest}"


def _validate_identity(value: str) -> str:
    value = value.strip().lower()
    if not _SMTP_RE.fullmatch(value):
        raise ValueError("identity must be one exact SMTP address; wildcards and aliases are not allowed")
    return value


def _context(actor: str, correlation_id: str) -> OperationContext:
    kwargs: dict[str, Any] = {"actor": actor.strip(), "source": "exchange-m365-mcp"}
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


class ExchangeOnlineMailboxDebugTransport:
    """Exact-identity mailbox state probe using the existing view-only Exchange identity."""

    def __init__(self, settings: Settings) -> None:
        if not settings.exchange_backend_read_only:
            raise ValueError("EXCHANGE_BACKEND_READ_ONLY=true is required")
        if not settings.exchange_view_only_rbac_attested:
            raise ValueError("EXCHANGE_VIEW_ONLY_RBAC_ATTESTED=true is required")
        if not settings.exchange_configured:
            raise ValueError("Exchange read-only backend credentials are required")
        self.settings = settings

    async def inspect(self, address: str) -> dict[str, Any]:
        script = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
$commands = @('Get-Mailbox')
try {
    Connect-ExchangeOnline `
        -AppId $env:MCP_EXCHANGE_APP_ID `
        -CertificateThumbprint $env:MCP_EXCHANGE_CERT_THUMBPRINT `
        -Organization $env:MCP_EXCHANGE_ORGANIZATION `
        -CommandName $commands `
        -ShowBanner:$false
    $mailbox = Get-Mailbox -Identity $env:MCP_EXCHANGE_TARGET_ADDRESS -ErrorAction SilentlyContinue
    if ($null -eq $mailbox) {
        [pscustomobject]@{ exists = $false } | ConvertTo-Json -Compress
    } else {
        [pscustomobject]@{
            exists = $true
            RecipientTypeDetails = $mailbox.RecipientTypeDetails.ToString()
            ArchiveStatus = $mailbox.ArchiveStatus.ToString()
            HiddenFromAddressListsEnabled = [bool]$mailbox.HiddenFromAddressListsEnabled
            LitigationHoldEnabled = [bool]$mailbox.LitigationHoldEnabled
            ForwardingConfigured = [bool]($null -ne $mailbox.ForwardingAddress -or $null -ne $mailbox.ForwardingSmtpAddress)
            DeliverToMailboxAndForward = [bool]$mailbox.DeliverToMailboxAndForward
            EmailAddressCount = @($mailbox.EmailAddresses).Count
        } | ConvertTo-Json -Depth 3 -Compress
    }
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
""".strip()
        env = os.environ.copy()
        env.update(
            {
                "MCP_EXCHANGE_APP_ID": self.settings.exchange_app_id,
                "MCP_EXCHANGE_CERT_THUMBPRINT": self.settings.exchange_certificate_thumbprint,
                "MCP_EXCHANGE_ORGANIZATION": self.settings.exchange_organization,
                "MCP_EXCHANGE_TARGET_ADDRESS": address,
            }
        )
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
            raise ExchangeMailboxDebugError("Exchange debug response exceeded the byte limit")
        if process.returncode != 0:
            detail = " (backend returned a redacted error)" if stderr else ""
            raise ExchangeMailboxDebugError(f"Exchange mailbox debug command failed{detail}")
        try:
            payload = json.loads(stdout or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExchangeMailboxDebugError("Exchange mailbox debug returned invalid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ExchangeMailboxDebugError("Exchange mailbox debug returned an invalid object")
        return {str(key): value for key, value in payload.items()}


def register_mailbox_debug_tools(mcp: FastMCP, settings: Settings) -> None:
    if not settings.exchange_mailbox_debug_enabled:
        return

    transport = ExchangeOnlineMailboxDebugTransport(settings)

    @mcp.tool()
    async def exchange_debug_mailbox(
        identity: str,
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        address = _validate_identity(identity)
        observed = await transport.inspect(address)
        context = _context(actor, correlation_id)
        ref = _mailbox_ref(address)
        output = {
            "mailboxRef": ref,
            "exists": bool(observed.get("exists")),
        }
        if output["exists"]:
            output.update(
                {
                    "recipientTypeDetails": str(observed.get("RecipientTypeDetails", ""))[:64],
                    "archiveStatus": str(observed.get("ArchiveStatus", ""))[:64],
                    "hiddenFromAddressListsEnabled": bool(
                        observed.get("HiddenFromAddressListsEnabled")
                    ),
                    "litigationHoldEnabled": bool(observed.get("LitigationHoldEnabled")),
                    "forwardingConfigured": bool(observed.get("ForwardingConfigured")),
                    "deliverToMailboxAndForward": bool(
                        observed.get("DeliverToMailboxAndForward")
                    ),
                    "emailAddressCount": min(int(observed.get("EmailAddressCount", 0) or 0), 1000),
                }
            )
        result = OperationResult(
            operation="exchange.mailbox.debug.get",
            phase=OperationPhase.OBSERVE,
            status=OperationStatus.SUCCEEDED,
            context=context,
            output=output,
        )
        audit = AuditEvent(
            operation="exchange.mailbox.debug.get",
            phase=OperationPhase.OBSERVE,
            risk=RiskLevel.READ_ONLY,
            context=context,
            target=ref,
            status=OperationStatus.SUCCEEDED,
            metadata={"reason": _reason(reason)},
        )
        payload = result.model_dump(mode="json")
        payload["audit"] = audit.model_dump(mode="json")
        return payload
