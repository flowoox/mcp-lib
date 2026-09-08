# MCP employee access tiers and authentication boundary

Status: architecture baseline for multi-user administrative MCP deployments.

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

For HTTP MCP, use OAuth/OIDC as the application authentication boundary. The MCP resource server validates every access token for signature, issuer, expiry/not-before, audience/resource and required scopes. Access tokens must not be accepted through query strings and a token issued for one MCP audience must fail at every other tier.

Do not use a shared long-lived bearer token as an employee credential. The repository's current static `MCP_AUTH_TOKEN` mode is a bootstrap/lab boundary for a single trusted technical client, not the target multi-user design.

### Windows / Kerberos SSO

Kerberos can still provide seamless employee SSO without making Kerberos the MCP protocol credential. In a domain environment, terminate Integrated Windows Authentication at a trusted identity-aware gateway or identity provider. That component maps the authenticated AD identity and group membership to an OAuth/OIDC authorization flow and issues a short-lived token for the MCP resource.

Do not expose NTLM/Kerberos authentication on an Internet-facing MCP endpoint and do not accept raw user passwords in an MCP tool. The MCP service itself should not implement a password login form, which removes the normal online password brute-force surface from the MCP process.

## Initial tiers

| Tier | Example audience | Intended users | Typical scopes | Backend boundary |
| --- | --- | --- | --- | --- |
| Employee read | `mcp-files-read` | approved employees | `mcp.files.search`, `mcp.files.read` | filesystem/share account with read ACL only |
| IT observe | `mcp-it-observe` | IT staff | `mcp.infra.observe`, `mcp.exchange.debug` | separate read-only identities per system |
| IT change | `mcp-it-change` | administrators | `mcp.exchange.manage`, selected lifecycle scopes | separate write identities; approval + verify |
| Network core | `mcp-network-core` | network administrators only | `mcp.network.core.debug` initially | dedicated TACACS/RADIUS/API identity; read/debug first |
| Break glass | separate endpoint/audience | emergency administrators | explicitly selected recovery scopes | normally disabled, separately audited |

Keep firewall/core-switch access in a separate deployment even if the same administrator is allowed to use both Exchange and network MCPs. Separate processes, audiences and backend credentials reduce blast radius if one MCP instance, client token or downstream credential is compromised.

## RBAC mapping

Use identity-provider groups or application roles as the source of truth, for example:

```text
GG-MCP-Files-Read      -> mcp.files.search, mcp.files.read
GG-MCP-IT-Observe      -> mcp.infra.observe, mcp.exchange.debug
GG-MCP-Exchange-Admin  -> mcp.exchange.manage
GG-MCP-Network-Core    -> mcp.network.core.debug
```

Authorization must be enforced in more than one layer:

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

## Brute-force and abuse resistance

Password attack controls belong at the enterprise identity provider because the MCP server should not authenticate usernames/passwords itself. Apply MFA, smart lockout/password-spray detection and Conditional Access there. At the MCP ingress additionally enforce request-rate and connection limits, payload-size limits, request timeouts and repeated-401/403 throttling. Administrative tiers should normally also require private network/VPN/tunnel reachability.

A stolen valid token is a different threat than brute force. Limit that blast radius with short token lifetimes, audience binding, narrow scopes, device/user policy, backend least privilege, and high-risk approval gates.

## Audit identity

The trusted actor must come from validated token claims such as stable subject/object ID plus the relevant user display/login claim. Tool callers must not be able to choose their own audit identity.

The current shared operation schema accepts an `actor` field supplied by the MCP tool call. Until the authentication layer injects and binds actor identity from validated claims, production multi-user administrative rollout is blocked. Preserve correlation IDs and structured audit events, but treat caller-provided actor strings as untrusted metadata.

Recommended audit event fields include:

- token subject/object ID and tenant/issuer
- effective MCP audience and scopes
- operation/tool and target reference
- correlation and idempotency IDs
- approval identity for high-risk changes
- success/failure/rejection and verification outcome
- source device/network metadata captured by the ingress where policy permits

Never log access tokens, refresh tokens, passwords, certificate private keys or upstream API credentials.

## Exchange-specific boundary

Keep the existing Exchange read identity and the mailbox-management identity separate. For the management service principal, use Exchange Application RBAC/custom role groups and an applicable recipient/resource scope instead of assigning a broad tenant administrator role. The MCP itself independently restricts commands and allowed mailbox domains, so Exchange RBAC remains the authoritative downstream authorization boundary even if MCP code is bypassed.

## Rollout gates

Before employee access is enabled:

- replace shared static employee bearer authentication with OAuth/OIDC token validation
- derive actor from validated identity claims
- implement per-audience/per-scope authorization tests
- deploy separate tier endpoints and downstream identities
- enforce private ingress/tunnel plus TLS
- turn on centralized security/audit logging without secrets
- test wrong-audience, wrong-scope, expired-token and removed-group denial paths
- perform an authorization review for every write-enabled MCP service
