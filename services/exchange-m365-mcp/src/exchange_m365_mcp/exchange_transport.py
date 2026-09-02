from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    AcceptedDomainObservation,
    InboundConnectorObservation,
    OrganizationObservation,
    OutboundConnectorObservation,
    RemoteDomainObservation,
    TransportConfigObservation,
)


class ExchangeTransportError(RuntimeError):
    """Raised when the fixed Exchange Online observation adapter fails closed."""


def _text(value: Any, *, max_length: int = 128) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _count(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return min(len(value), 10_000)
    return 1


def _stable_ref(value: Any, *, prefix: str) -> str:
    normalized = _text(value, max_length=512).strip().casefold()
    if not normalized:
        raise ExchangeTransportError("Exchange returned an object without a stable identity")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _domain_name(value: Any) -> str:
    return _text(value, max_length=253).strip().lower()


_SCRIPT_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
""".strip()

_SCRIPT_CONNECT = r"""
Connect-ExchangeOnline `
    -AppId $env:MCP_EXCHANGE_APP_ID `
    -CertificateThumbprint $env:MCP_EXCHANGE_CERT_THUMBPRINT `
    -Organization $env:MCP_EXCHANGE_ORGANIZATION `
    -CommandName $commands `
    -ShowBanner:$false
""".strip()

_SCRIPT_FINALLY = r"""
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
""".strip()


class ExchangeOnlineReadOnlyTransport:
    """Stable EXO PowerShell adapter exposing only fixed Get-* observation operations."""

    def __init__(self, settings: Settings) -> None:
        if not settings.exchange_backend_read_only:
            raise ValueError(
                "EXCHANGE_BACKEND_READ_ONLY=true is required for the Exchange reader identity"
            )
        if not settings.exchange_view_only_rbac_attested:
            raise ValueError(
                "EXCHANGE_VIEW_ONLY_RBAC_ATTESTED=true is required for the Exchange service principal"
            )
        if not settings.exchange_configured:
            raise ValueError(
                "EXCHANGE_ORGANIZATION, EXCHANGE_APP_ID and EXCHANGE_CERTIFICATE_THUMBPRINT are required"
            )
        self.settings = settings

    @property
    def read_only(self) -> bool:
        return self.settings.exchange_backend_read_only

    @staticmethod
    def _parameters(query: ReadOnlyQuery) -> None:
        if query.parameters:
            raise ValueError("Exchange observation operations do not accept free-form parameters")
        if query.page.cursor is not None:
            raise ValueError("Exchange Observe v1 is intentionally first-page-only")

    def _script(self, query: ReadOnlyQuery) -> str:
        self._parameters(query)
        fetch_size = min(query.page.limit + 1, self.settings.exchange_max_page_size + 1)
        operation = query.operation
        if operation == "exchange.organization.get":
            commands = "@('Get-OrganizationConfig')"
            body = r"""
$result = Get-OrganizationConfig | Select-Object IsFederated,OAuth2ClientProfileEnabled,PublicFoldersEnabled,PublicFolderMailboxesMigrationComplete,FocusedInboxOn
""".strip()
        elif operation == "exchange.accepted_domains.list":
            commands = "@('Get-AcceptedDomain')"
            body = f"""
$result = Get-AcceptedDomain -ResultSize {fetch_size} | Select-Object `
    @{{n='DomainName';e={{$_.DomainName.ToString()}}}},DomainType,Default,AddressBookEnabled,MatchSubDomains
""".strip()
        elif operation == "exchange.remote_domains.list":
            commands = "@('Get-RemoteDomain')"
            body = f"""
$result = Get-RemoteDomain -ResultSize {fetch_size} | Select-Object @{{n='DomainName';e={{$_.DomainName.ToString()}}}},AllowedOOFType,AutoForwardEnabled,AutoReplyEnabled,DeliveryReportEnabled,NDREnabled,TNEFEnabled
""".strip()
        elif operation == "exchange.inbound_connectors.list":
            commands = "@('Get-InboundConnector')"
            body = f"""
$result = Get-InboundConnector -ResultSize {fetch_size} | Select-Object Identity,Enabled,ConnectorType,RequireTls,RestrictDomainsToCertificate,RestrictDomainsToIPAddresses,CloudServicesMailEnabled,TreatMessagesAsInternal,SenderIPAddresses,SenderDomains
""".strip()
        elif operation == "exchange.outbound_connectors.list":
            commands = "@('Get-OutboundConnector')"
            body = f"""
$result = Get-OutboundConnector -ResultSize {fetch_size} | Select-Object Identity,Enabled,ConnectorType,RouteAllMessagesViaOnPremises,UseMXRecord,TlsSettings,RecipientDomains,SmartHosts
""".strip()
        elif operation == "exchange.transport_config.get":
            commands = "@('Get-TransportConfig')"
            body = r"""
$result = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled,AllowLegacyTLSClients,SafetyNetHoldTime,MaxReceiveSize,MaxSendSize
""".strip()
        else:
            raise PermissionError("Exchange operation is not implemented by the fixed adapter")
        return "\n".join(
            (
                _SCRIPT_PREAMBLE,
                f"$commands = {commands}",
                "try {",
                _SCRIPT_CONNECT,
                body,
                "$result | ConvertTo-Json -Depth 5 -Compress",
                _SCRIPT_FINALLY,
            )
        )

    async def _invoke(self, script: str, *, timeout_seconds: float, max_response_bytes: int) -> Any:
        env = os.environ.copy()
        env.update(
            {
                "MCP_EXCHANGE_APP_ID": self.settings.exchange_app_id,
                "MCP_EXCHANGE_CERT_THUMBPRINT": self.settings.exchange_certificate_thumbprint,
                "MCP_EXCHANGE_ORGANIZATION": self.settings.exchange_organization,
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
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        if len(stdout) > max_response_bytes:
            raise ExchangeTransportError("Exchange response exceeded the configured byte limit")
        if process.returncode != 0:
            detail = ""
            if stderr:
                detail = " (PowerShell returned a redacted backend error)"
            raise ExchangeTransportError(f"Exchange observation command failed{detail}")
        if not stdout.strip():
            return []
        try:
            return json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExchangeTransportError("Exchange returned invalid JSON") from exc

    def _project(self, operation: str, row: Mapping[str, Any]) -> dict[str, Any]:
        if operation == "exchange.organization.get":
            return OrganizationObservation(
                federation_enabled=_boolean(row.get("IsFederated")),
                oauth2_client_profile_enabled=_boolean(row.get("OAuth2ClientProfileEnabled")),
                public_folders_enabled=_text(row.get("PublicFoldersEnabled")),
                public_folder_mailboxes_migration_complete=_boolean(
                    row.get("PublicFolderMailboxesMigrationComplete")
                ),
                focused_inbox_enabled=_boolean(row.get("FocusedInboxOn")),
            ).model_dump(mode="json")
        if operation == "exchange.accepted_domains.list":
            domain = _domain_name(row.get("DomainName"))
            return AcceptedDomainObservation(
                domain_ref=_stable_ref(domain, prefix="domain"),
                domain_name=domain if self.settings.exchange_return_domain_names else None,
                domain_type=_text(row.get("DomainType")),
                default=_boolean(row.get("Default")),
                address_book_enabled=_boolean(row.get("AddressBookEnabled")),
                match_subdomains=_boolean(row.get("MatchSubDomains")),
            ).model_dump(mode="json")
        if operation == "exchange.remote_domains.list":
            domain = _domain_name(row.get("DomainName"))
            return RemoteDomainObservation(
                domain_ref=_stable_ref(domain, prefix="domain"),
                domain_name=domain if self.settings.exchange_return_domain_names else None,
                allowed_oof_type=_text(row.get("AllowedOOFType")),
                auto_forward_enabled=_boolean(row.get("AutoForwardEnabled")),
                auto_reply_enabled=_boolean(row.get("AutoReplyEnabled")),
                delivery_report_enabled=_boolean(row.get("DeliveryReportEnabled")),
                ndr_enabled=_boolean(row.get("NDREnabled")),
                tnef_enabled=_boolean(row.get("TNEFEnabled")),
            ).model_dump(mode="json")
        if operation == "exchange.inbound_connectors.list":
            return InboundConnectorObservation(
                connector_ref=_stable_ref(row.get("Identity"), prefix="connector"),
                enabled=_boolean(row.get("Enabled")),
                connector_type=_text(row.get("ConnectorType")),
                require_tls=_boolean(row.get("RequireTls")),
                restrict_domains_to_certificate=_boolean(row.get("RestrictDomainsToCertificate")),
                restrict_domains_to_ip_addresses=_boolean(row.get("RestrictDomainsToIPAddresses")),
                cloud_services_mail_enabled=_boolean(row.get("CloudServicesMailEnabled")),
                treat_messages_as_internal=_boolean(row.get("TreatMessagesAsInternal")),
                sender_ip_count=_count(row.get("SenderIPAddresses")),
                sender_domain_count=_count(row.get("SenderDomains")),
            ).model_dump(mode="json")
        if operation == "exchange.outbound_connectors.list":
            return OutboundConnectorObservation(
                connector_ref=_stable_ref(row.get("Identity"), prefix="connector"),
                enabled=_boolean(row.get("Enabled")),
                connector_type=_text(row.get("ConnectorType")),
                route_all_messages_via_on_premises=_boolean(
                    row.get("RouteAllMessagesViaOnPremises")
                ),
                use_mx_record=_boolean(row.get("UseMXRecord")),
                tls_settings=_text(row.get("TlsSettings")),
                recipient_domain_count=_count(row.get("RecipientDomains")),
                smart_host_count=_count(row.get("SmartHosts")),
            ).model_dump(mode="json")
        if operation == "exchange.transport_config.get":
            return TransportConfigObservation(
                smtp_client_authentication_disabled=_boolean(
                    row.get("SmtpClientAuthenticationDisabled")
                ),
                allow_legacy_tls_clients=_boolean(row.get("AllowLegacyTLSClients")),
                safety_net_hold_time=_text(row.get("SafetyNetHoldTime")),
                max_receive_size=_text(row.get("MaxReceiveSize")),
                max_send_size=_text(row.get("MaxSendSize")),
            ).model_dump(mode="json")
        raise PermissionError("Exchange operation is not implemented by the fixed projection")

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        payload = await self._invoke(
            self._script(query),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if isinstance(payload, Mapping):
            raw_rows = [payload]
        elif isinstance(payload, list):
            raw_rows = payload
        else:
            raise ExchangeTransportError("Exchange response must be an object or array")
        if not all(isinstance(row, Mapping) for row in raw_rows):
            raise ExchangeTransportError("Exchange response contained a non-object row")
        truncated = len(raw_rows) > query.page.limit
        rows = [self._project(query.operation, row) for row in raw_rows[: query.page.limit]]
        payload_bytes = len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return ReadOnlyPage(
            items=rows,
            truncated=truncated,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.exchange_cache_max_age_seconds),
        )
