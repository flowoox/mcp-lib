# PKI MCP

Production-oriented, product-neutral **Observe v1** diagnostics for Microsoft Active Directory Certificate Services (AD CS).

The supported observation boundary was re-verified on 2026-09-01 against Microsoft documentation. `ICertView` is the supported programmatic interface for properly authorized clients to view the Certificate Services database, and Microsoft documents an explicit CA permission to grant or restrict **View CA database** access. Microsoft also documents `ICertConfig` for public Certificate Services configuration data. This MCP intentionally does **not** automate `certutil`: Microsoft warns that `certutil` is not recommended for production code and does not guarantee live-site/application compatibility.

## Fail-closed deployment

Run the service from a Windows management host with the Certificate Services client components and PowerShell available. Each logical `PKI_TARGETS_JSON` entry points to a dedicated constrained Kerberos WinRM/JEA endpoint and the exact `ServerName\CAName` configuration string. Real server names, CA names, topology and identities remain deployment configuration and are never committed to the public library.

The backend identity must be dedicated and minimally granted for observation. In particular, deployment must explicitly grant **View CA database** on the target CA and attest both:

- `PKI_BACKEND_READ_ONLY=true`
- `PKI_BACKEND_VIEW_CA_DATABASE_ATTESTED=true`

The MCP fails closed when either attestation is absent. Do not satisfy the contract with Domain Admin, Enterprise Admin or an unrestricted PowerShell endpoint. The JEA endpoint should expose only the fixed read primitives required by the repository-owned probes (`Get-Service`, bounded registry/certificate-store reads, `Get-WinEvent`, and the Certificate Services view COM object).

## Observe v1 tools

- `pki_observe_ca`: CA service state, CA certificate validity and CRL period/overlap metadata.
- `pki_list_expiring_certificates`: bounded Certificate Services database view restricted to a caller-bounded future expiry window. The projection returns request ID, certificate-template identifier and validity only; requester identity, subject, UPN, serial number and certificate body are excluded.
- `pki_observe_revocation_publication`: counts configured CRL/CA-certificate publication targets and reports whether the CA certificate itself contains CDP/AIA extensions. Publication URLs are not returned.
- `pki_list_events`: bounded Certification Authority application-event metadata without message bodies.
- `pki_diagnostic_bundle`: aggregate-first CA, revocation-publication, expiring-certificate and warning/error-event evidence under one shared query budget.

`ICertView` does not provide a continuation-token contract suitable for an agent-facing crawler. Observe v1 therefore deliberately exposes one bounded page only. If more expiring rows exist, `truncated=true` is returned and no cursor is exposed.

## Query and privacy safety

`mcp-common` `ReadOnlyConnector` and `QueryBudget` enforce explicit operation allowlisting, request/item/response-byte limits, timeouts, concurrency, rate limits and total fan-out budgets. The adapter never accepts arbitrary PowerShell, COM class names, database columns, database restrictions, certificate-store paths, registry paths, hosts or CA configuration strings from callers.

The service deliberately does not return:

- private keys, PFX/PKCS#12 material, certificate bodies or unrestricted store exports;
- requester names, UPNs, e-mail addresses, certificate subjects or full serial numbers;
- real CRL/AIA publication URLs;
- certificate-template AD objects or template security descriptors;
- CA database messages or event message bodies.

Microsoft's current certificate-template management documentation describes Domain Admin membership for template administration and stores enterprise templates in AD DS. Observe v1 therefore does not turn the PKI service into a template-management or generic AD query surface. Safe template-policy inspection can be added only after a separate least-privilege read contract is proven, preferably reusing `ad-mcp`.

## Explicitly not exposed

There is no certificate issuance, approval, denial, revocation, key recovery, CA backup/restore, CRL publication, template publishing/editing, CA configuration change, service restart, arbitrary PowerShell/CIM/WMI, arbitrary registry/store browsing or generic Certificate Services database query.

Any future state-changing PKI capability must be a separate operation lifecycle using `plan -> approval -> change -> verify`, a dedicated least-privilege write identity, idempotency, pre-state capture and an explicit rollback declaration where technically possible.

## Primary Microsoft references

- Viewing the Certificate Services Database: https://learn.microsoft.com/en-us/windows/win32/seccrypto/viewing-the-certificate-services-database
- ICertView: https://learn.microsoft.com/en-us/windows/win32/api/certview/nn-certview-icertview
- ICertView::SetRestriction: https://learn.microsoft.com/en-us/windows/win32/api/certview/nf-certview-icertview-setrestriction
- ICertConfig: https://learn.microsoft.com/en-us/windows/win32/api/certcli/nn-certcli-icertconfig
- Certificate templates: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates
- certutil warning: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
