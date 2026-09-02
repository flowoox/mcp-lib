# Exchange Online / Microsoft 365 MCP

`exchange-m365-mcp` is a product-neutral, bounded **read-only** diagnostics service for Exchange Online configuration and Microsoft 365 service health. It follows the repository-wide `observe -> plan -> change -> verify` model; this service implements **Observe v1 only**.

## Security boundary

The service deliberately uses two deployment-owned least-privilege identities instead of one broad tenant administrator:

- **Exchange Online:** certificate-based app-only Exchange Online PowerShell. The Entra application needs the Exchange Online app-only authentication gate, while its effective Exchange permissions must be restricted through Exchange RBAC to a dedicated view-only assignment. `EXCHANGE_VIEW_ONLY_RBAC_ATTESTED=true` is a deployment assertion that this has been done. Only a static list of `Get-*` cmdlets is imported with `Connect-ExchangeOnline -CommandName`; arbitrary PowerShell is impossible through the MCP contract.
- **Microsoft Graph:** a separate client-credentials identity carrying only the `ServiceHealth.Read.All` application permission. `M365_GRAPH_SERVICE_HEALTH_PERMISSION_ATTESTED=true` is required before startup.

The service fails closed unless both backends are explicitly attested read-only. Tenant IDs, application IDs, certificate thumbprints and secrets remain deployment configuration and are never returned through capabilities or tools. The certificate private key stays in the PowerShell host certificate store; the MCP only receives the thumbprint.

## Observe operations

Exchange Online operations are fixed to organization configuration, accepted domains, remote domains, inbound connectors, outbound connectors and transport configuration. Microsoft Graph operations are fixed to v1.0 service-health overviews and Exchange Online service issues. `exchange_m365_diagnostic_bundle` performs aggregate tenant/service-health checks before bounded connector/domain drill-down and shares one query budget across the entire bundle.

Default projections minimize topology and tenant data. Domain names are represented by stable SHA-256-derived references unless `EXCHANGE_RETURN_DOMAIN_NAMES=true` is explicitly configured. Connector identities are always hashed. Sender IP addresses, sender/recipient domain lists, certificate subjects and smart hosts are reduced to counts. Service issue bodies, impact descriptions and posts are never returned.

## Explicit exclusions

Observe v1 has no mailbox or recipient enumeration, message bodies, attachments, message trace, eDiscovery/content search, mailbox export, transport-rule changes, connector/domain mutations, arbitrary Graph paths/OData filters, arbitrary PowerShell, user-provided cmdlets, or write tools. The preview Exchange Online Admin API is not used; the adapter stays on supported Exchange Online PowerShell plus Microsoft Graph v1.0 service communications.

## Deployment prerequisites

Install PowerShell 7 and the supported `ExchangeOnlineManagement` module on the service host. Provision the Exchange app certificate in the PowerShell execution identity's certificate store. Register the Entra service principal in Exchange and grant only the view-only RBAC roles needed for the fixed observation cmdlets. Provision a separate Graph application with only `ServiceHealth.Read.All` application permission and admin consent. Keep all credentials outside the public repository.

Start only after setting the two read-only attestations and backend credentials. MCP HTTP/auth/trust-boundary configuration follows `mcp-common` and the other Infrastructure MCP services.
