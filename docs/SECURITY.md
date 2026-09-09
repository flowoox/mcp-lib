# MCP security and deployment boundary

Every HTTP MCP service in this repository passes explicit `TransportSecuritySettings` to FastMCP. Binding to `0.0.0.0` is only a socket decision; it is never treated as an implicit Host or Origin allowlist.

## Internal deployments

`MCP_TRUST_BOUNDARY=internal` is the default for loopback-only development and private container-network consumers. DNS-rebinding protection remains enabled. The built-in allowlist accepts loopback hosts/origins and the service's Compose DNS name (`mcp-soulseek`, `mcp-archive`, or `mcp-traxx`). Add deployment-specific names through comma-separated `MCP_ALLOWED_HOSTS` and browser origins through `MCP_ALLOWED_ORIGINS`; do not disable the protection to make a proxy work.

Internal network reachability is not authorization. Keep these services unpublished unless the calling deployment provides its own authenticated control plane.

## External or tenant-crossing deployments

External mode always requires an explicit HTTPS `MCP_PUBLIC_URL` for non-loopback deployments plus explicit Host/Origin allowlists. Authentication has two deliberately separate modes; configuring both fails closed.

### Bootstrap / single trusted technical client

Use the static bearer only for a lab/bootstrap or one trusted technical client:

```text
MCP_TRUST_BOUNDARY=external
MCP_PUBLIC_URL=https://mcp.example.test/mcp
MCP_AUTH_TOKEN=<runtime secret>
MCP_ISSUER_URL=
MCP_ALLOWED_HOSTS=mcp.example.test,mcp.example.test:*
MCP_ALLOWED_ORIGINS=https://trusted-ui.example.test
```

The configured bearer token is verified only at the MCP resource server and is never returned by a tool. This mode is not an employee identity or multi-user RBAC boundary.

### Multi-user OAuth/OIDC resource server

Administrative employee access must use OIDC mode instead of a shared bearer:

```text
MCP_TRUST_BOUNDARY=external
MCP_PUBLIC_URL=https://mcp.example.test/mcp
MCP_AUTH_TOKEN=
MCP_ISSUER_URL=https://idp.example.test/tenant
MCP_ALLOWED_HOSTS=mcp.example.test,mcp.example.test:*
MCP_ALLOWED_ORIGINS=https://trusted-ui.example.test
```

OIDC mode validates an allowlisted signing algorithm, JWT signature, exact issuer, expiry/not-before, one exact audience/resource and the service's required scopes/application roles. A token with a different audience, a multi-valued audience, insufficient scope, invalid time window or unsigned/unapproved algorithm fails closed. Authorization-server discovery and JWKS retrieval do not follow redirects, are response-size bounded and must remain on the configured issuer origin.

Known administrative service tiers use explicit deny-by-default scopes such as `mcp.files.read`/`mcp.files.search`, `mcp.infra.observe`, `mcp.exchange.manage` and `mcp.network.core.debug`. OIDC deployments for a service without a known tier must provide explicit non-generic `required_scopes`; the generic `mcp` scope is bootstrap-only and is not accepted as a multi-user authorization tier.

The trusted audit actor is derived from validated OIDC identity claims. Caller-supplied `actor` fields cannot replace that identity in OIDC mode. Employee access tokens must never be forwarded to Exchange, firewalls, switches or other downstream systems; those connectors retain separate server-side credentials and their own least-privilege authorization controls.

For production administrative tiers, keep the endpoint behind private ingress/VPN/tunnel where practical, enforce rate/connection limits at ingress, use short-lived tokens and centralized audit logging without secrets, and test removed-role, wrong-audience, wrong-scope and actor-forgery denial through the real identity-provider and ingress path before rollout.

## Traxx credential destination policy

Traxx service tokens, actor tokens and proxy/WAF headers are credential-bearing state. `configure_traxx` therefore cannot move an already configured/credentialed connector to an arbitrary origin. The initial `TRAXX_URL` origin is trusted automatically; additional migration targets must be pre-approved by the operator with comma-separated `TRAXX_ALLOWED_ORIGINS`.

A completely unconfigured and credential-free connector may choose its first origin. After that origin or any credential exists, an origin change without an operator allowlist is rejected. Base URLs must be bare HTTP(S) origins and may not contain URL userinfo, application paths, queries, or fragments.

TLS verification is on by default. Persisting or using `verify_tls=false` is rejected unless the deployment explicitly sets `TRAXX_ALLOW_INSECURE_TLS=true`; that switch is intended only for isolated development/test environments.

## Proxy headers

Host validation uses the actual HTTP `Host` header reaching FastMCP. Do not trust arbitrary `Forwarded` or `X-Forwarded-Host` values to expand the MCP allowlist. A reverse proxy should normalize the upstream Host header to one of the explicitly configured values and terminate TLS before forwarding into the private service network.
