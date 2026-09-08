# Exchange Online / Microsoft 365 MCP

`exchange-m365-mcp` is a product-neutral, bounded Exchange Online and Microsoft 365 service. Its default deployment remains **read-only** and implements Exchange configuration diagnostics plus Microsoft 365 service-health observation. Two optional features can be enabled independently: exact-identity mailbox debugging and an approved shared-mailbox provisioning lifecycle.

## Security boundaries

The service deliberately separates identities by privilege instead of turning one tenant-wide administrator into an MCP credential.

- **Exchange read-only:** certificate-based app-only Exchange Online PowerShell. The Entra application needs the Exchange Online app-only authentication gate, while its effective Exchange permissions must be restricted through Exchange RBAC to a dedicated view-only assignment. `EXCHANGE_VIEW_ONLY_RBAC_ATTESTED=true` is a deployment assertion that this has been done. Only a static list of `Get-*` cmdlets is imported with `Connect-ExchangeOnline -CommandName`; arbitrary PowerShell is impossible through the MCP contract.
- **Exchange mailbox management:** a second application ID and certificate are mandatory. `EXCHANGE_RECIPIENT_WRITE_RBAC_ATTESTED=true` asserts that Exchange Application RBAC has been configured for the management service principal with only the recipient-management permissions and write scope required for the approved mailbox population. The service also requires an exact `EXCHANGE_MAILBOX_ALLOWED_DOMAINS` allowlist. Reusing the read-only app ID or certificate fails startup.
- **Microsoft Graph:** a separate client-credentials identity carrying only the `ServiceHealth.Read.All` application permission. `M365_GRAPH_SERVICE_HEALTH_PERMISSION_ATTESTED=true` is required before startup.

Tenant IDs, application IDs, certificate thumbprints and secrets remain deployment configuration and are never returned through capabilities or tools. Certificate private keys remain in the PowerShell host certificate store; MCP receives only thumbprints. The write approval secret is runtime configuration and must contain at least 32 bytes.

## Observe and debug operations

The baseline Exchange Online operations are fixed to organization configuration, accepted domains, remote domains, inbound connectors, outbound connectors and transport configuration. Microsoft Graph operations are fixed to v1.0 service-health overviews and Exchange Online service issues. `exchange_m365_diagnostic_bundle` performs aggregate tenant/service-health checks before bounded connector/domain drill-down and shares one query budget across the entire bundle.

`EXCHANGE_MAILBOX_DEBUG_ENABLED=true` adds `exchange_debug_mailbox`. The tool requires one exact SMTP address and does not support aliases, wildcards or enumeration. It returns a hashed mailbox reference plus a minimized set of diagnostic state such as recipient type, archive state, forwarding-present boolean, address count and selected flags. It never returns mailbox content, messages, folders, message traces or complete proxy-address values.

## Shared-mailbox management

Shared-mailbox writes are **off by default**. They are registered only when all of the following are configured:

- `EXCHANGE_WRITES_ENABLED=true`
- `EXCHANGE_RECIPIENT_WRITE_RBAC_ATTESTED=true`
- a dedicated `EXCHANGE_MANAGEMENT_APP_ID`
- a dedicated `EXCHANGE_MANAGEMENT_CERTIFICATE_THUMBPRINT`
- at least one exact `EXCHANGE_MAILBOX_ALLOWED_DOMAINS`
- `EXCHANGE_APPROVAL_SECRET` with at least 32 bytes

The first management lifecycle intentionally supports **shared mailboxes only**. It exposes plan, change and verify operations. Planning captures pre-state and returns an approval binding. The change requires a short-lived signed approval grant bound to the exact operation, target, idempotency key and desired mailbox state. Creation is idempotent and post-change state is verified. User-provided values are passed to PowerShell through process environment variables; callers cannot provide cmdlet names or PowerShell fragments.

User mailboxes, password bootstrap, license assignment, mailbox deletion, permissions/delegation, forwarding changes and other recipient mutations are deliberately not part of this first write boundary. Those should be added as separate lifecycle capabilities with their own least-privilege scopes and verification.

## Explicit exclusions

There is no mailbox or recipient enumeration, message body or attachment access, message trace, eDiscovery/content search, mailbox export, arbitrary Graph path/OData filter, arbitrary PowerShell, user-provided cmdlets or caller-selected Exchange commands. Mailbox management cannot target a domain outside the configured exact-domain allowlist.

## Deployment prerequisites

Install PowerShell 7 and a supported `ExchangeOnlineManagement` module on the service host. Provision separate read and management application certificates in the PowerShell execution identity's certificate store. Register both service principals in Exchange. Grant the read principal only view-only Exchange RBAC. If mailbox management is enabled, grant the management principal a custom Exchange Application RBAC assignment and write scope restricted to the intended recipient population rather than tenant-wide administrator privileges.

Provision the separate Graph application with only `ServiceHealth.Read.All` application permission and admin consent. Keep all credentials outside the public repository.

For network-facing MCP authentication and employee RBAC, follow `docs/MCP-ACCESS-TIERS.md`. The legacy shared `MCP_AUTH_TOKEN` boundary is suitable only as a bootstrap/lab mechanism for one trusted client; production multi-user administration requires identity-bound OAuth/OIDC tokens and per-tier scopes.
