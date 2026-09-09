# MCP employee access tiers and authentication boundary

Status: source-side OAuth/OIDC resource-server enforcement implemented; production identity-provider and ingress rollout still requires deployment evidence.

## Goal

MCP access for employees must never mean that every authenticated user receives every tool. Authentication establishes who the caller is; authorization then decides which MCP resource and which bounded tools that identity may invoke. Backend infrastructure credentials remain independent from employee credentials and are restricted per service and tier.

## Recommended request path

```text
employee MCP client
        |
        | OAuth 2.1 / OIDC authorization code + PKCE
        v
enterprise identity provider
(Entra ID / compatible OIDC authorization server)
        |
        | short-lived, audience-bound access token
        v
private MCP ingress / tunnel / reverse proxy
        |
        +----------------------+-----------------------+-----------------------+
        |                      |                       |                       |
        v                      v                       v                       v
files-read MCP          infra-observe MCP       exchange-admin MCP     network-core MCP
separate audience       separate audience       separate audience      separate audience
read backend identity   read backend identities write EXO identity     network debug identity
```

Administrative MCP endpoints should remain private. A cloud-hosted MCP client that cannot directly reach the internal network should use a vetted reverse-connect/tunnel mechanism instead of publishing the administration endpoint to the public Internet.

## Authentication

For HTTP MCP, use OAuth/OIDC as the application authentication boundary. The shared `mcp-common` resource-server boundary now validates JWT access tokens for an allowlisted signing algorithm, signature, exact issuer, expiry/not-before, exact audience/resource and required scopes. Authorization-server discovery is fail-closed, redirects are not followed, discovery/JWKS responses are size-bounded, and `jwks_uri` must stay on the configured issuer origin. The SDK `AuthSettings.resource_server_url` also publishes OAuth Protected Resource Metadata for the endpoint.

OIDC mode is selected for an external MCP endpoint by setting `MCP_TRUST_BOUNDARY=external`, configuring an HTTPS `MCP_PUBLIC_URL` plus `MCP_ISSUER_URL`, and leaving `MCP_AUTH_TOKEN` unset. The resource URL is the default exact token audience. A service may expose an explicit `mcp_oidc_audience` setting where a deployment needs a distinct application URI, but audience matching remains exact.

Do not use a shared long-lived bearer token as an employee credential. The repository's static `MCP_AUTH_TOKEN` mode remains a bootstrap/lab boundary for a single trusted technical client, not the target multi-user design. Static and OIDC modes both retain Host/Origin allowlisting and DNS-rebinding protection.

### Windows / Kerberos SSO

Kerberos can still provide seamless employee SSO without making Kerberos the MCP protocol credential. In a domain environment, terminate Integrated Windows Authentication at a trusted identity-aware gateway or identity provider. That component maps the authenticated AD identity and group membership to an OAuth/OIDC authorization flow and issues a short-lived token for the MCP resource.

Do not expose NTLM/Kerberos authentication on an Internet-facing MCP endpoint and do not accept raw user passwords in an MCP tool. The MCP service itself should not implement a password login form, which removes the normal online password brute-force surface from the MCP process.

## Initial tiers

| Tier | Example audience/resource | Intended users | Required scopes | Backend boundary |
| --- | --- | --- | --- | --- |
| Employee read | dedicated files MCP URL | approved employees | `mcp.files.search`, `mcp.files.read` | filesystem/share account with read ACL only |
| IT observe | dedicated observe MCP URL | IT staff | `mcp.infra.observe` | separate read-only identities per system |
| Exchange change | dedicated Exchange management MCP URL | administrators | `mcp.exchange.manage` | separate write identity; approval + verify |
| Network core | dedicated network MCP URL | network administrators only | `mcp.network.core.debug` | dedicated network debug identity; bounded target policy |
| Break glass | separate endpoint/audience | emergency administrators | explicitly selected recovery scopes | normally disabled, separately audited |

The shared security helper applies these scopes by service identity today for fileshare, network-core and the infrastructure-observe services it recognizes. Exchange requires `mcp.exchange.manage` whenever `EXCHANGE_WRITES_ENABLED=true`; a read-only Exchange deployment requires the observe scope instead.

Keep firewall/core-switch access in a separate deployment even if the same administrator is allowed to use both Exchange and network MCPs. Separate processes, audiences and backend credentials reduce blast radius if one MCP instance, client token or downstream credential is compromised.

## RBAC mapping

Use identity-provider groups or application roles as the source of truth, for example:

```text
GG-MCP-Files-Read      -> mcp.files.search, mcp.files.read
GG-MCP-IT-Observe      -> mcp.infra.observe
GG-MCP-Exchange-Admin  -> mcp.exchange.manage
GG-MCP-Network-Core    -> mcp.network.core.debug
```

The resource server accepts OAuth `scope`/`scp` values and application-role values from a validated `roles` claim. Prefer assigning the exact MCP application roles to identity-provider groups rather than teaching the MCP process a second broad group-to-permission language.

Authorization is enforced in more than one layer:

1. The ingress/resource server requires the correct audience and scope for the endpoint.
2. The MCP process registers only the tools belonging to that deployment profile.
3. Each downstream service identity has only the permissions required by those tools.
4. High-risk changes additionally require an operation-bound approval grant and post-change verification.

A UI hiding a tool is not an authorization control.

## Token and session controls

- short-lived access tokens; refresh tokens remain under the authorization server/client policy
- MFA for administrators; prefer phishing-resistant authentication for high-privilege groups where available
- Conditional Access/device compliance for administrative clients when the identity platform supports it
- explicit audience/resource binding per MCP tier
- deny-by-default scope evaluation
- immediate rejection of expired, future, unsigned, wrong-issuer, wrong-audience or insufficient-scope tokens
- never pass the employee MCP access token through to Exchange, firewalls, switches or other upstream APIs
- service-to-service credentials remain server-side and are separately rotated

A removed group/application-role assignment takes effect when the authorization server next issues or refreshes a short-lived access token. Keep administrative token lifetimes short enough that privilege removal does not depend on a long-lived cached bearer credential.

## Brute-force and abuse resistance

Password attack controls belong at the enterprise identity provider because the MCP server should not authenticate usernames/passwords itself. Apply MFA, smart lockout/password-spray detection and Conditional Access there. At the MCP ingress additionally enforce request-rate and connection limits, payload-size limits, request timeouts and repeated-401/403 throttling. Administrative tiers should normally also require private network/VPN/tunnel reachability.

A stolen valid token is a different threat than brute force. Limit that blast radius with short token lifetimes, audience binding, narrow scopes, device/user policy, backend least privilege, and high-risk approval gates.

## Audit identity

The trusted actor now comes from the validated request token when OIDC mode is active. `OperationContext` ignores a caller-supplied `actor` string and binds the audit principal to a stable token subject/object identifier plus the relevant display/login claim. The issuer is represented by a stable hash in the bounded actor string so identities from different issuers cannot silently collide. Static bootstrap and non-HTTP test contexts retain the legacy caller actor because they do not represent multi-user employee identity.

Recommended audit event fields include:

- token subject/object ID and tenant/issuer
- effective MCP audience and scopes
- operation/tool and target reference
- correlation and idempotency IDs
- approval identity for high-risk changes
- success/failure/rejection and verification outcome
- source device/network metadata captured by the ingress where policy permits

Never log access tokens, refresh tokens, passwords, certificate private keys or upstream API credentials. The OIDC verifier exposes only a minimized identity-claim set to application code and never forwards the employee token to downstream connectors.

## Exchange-specific boundary

Keep the existing Exchange read identity and the mailbox-management identity separate. For the management service principal, use Exchange Application RBAC/custom role groups and an applicable recipient/resource scope instead of assigning a broad tenant administrator role. The MCP itself independently restricts commands and allowed mailbox domains, so Exchange RBAC remains the authoritative downstream authorization boundary even if MCP code is bypassed.

When Exchange writes are enabled, the HTTP MCP resource requires `mcp.exchange.manage` before the tool layer is reached. Existing operation-bound approval grants, exact mailbox-domain allowlisting, separate management certificate/app identity, idempotency and post-change verification remain mandatory downstream controls; OIDC does not replace them.

## Rollout gates

Before employee access is enabled in production:

- configure a dedicated identity-provider audience/resource for each MCP tier
- assign the exact application scopes/roles to the approved groups
- deploy with OIDC mode rather than a shared static employee bearer
- verify the protected-resource metadata and authorization-server discovery path through the real ingress
- enforce private ingress/tunnel plus TLS and request-rate controls
- turn on centralized security/audit logging without secrets
- smoke-test valid employee/admin tokens and deny wrong-audience, wrong-scope, expired, not-yet-valid, unsigned and removed-role tokens
- verify caller-supplied `actor` values cannot change the audit principal
- perform an authorization review for every write-enabled MCP service

Source-side token validation, deny-default tier scopes and claim-bound `OperationContext` identity are implementation prerequisites, not substitutes for the final IdP/ingress/deployment evidence.
