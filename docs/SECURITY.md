# MCP security and deployment boundary

Every HTTP MCP service in this repository passes explicit `TransportSecuritySettings` to FastMCP. Binding to `0.0.0.0` is only a socket decision; it is never treated as an implicit Host or Origin allowlist.

## Internal deployments

`MCP_TRUST_BOUNDARY=internal` is the default for loopback-only development and private container-network consumers. DNS-rebinding protection remains enabled. The built-in allowlist accepts loopback hosts/origins and the service's Compose DNS name (`mcp-soulseek`, `mcp-archive`, or `mcp-traxx`). Add deployment-specific names through comma-separated `MCP_ALLOWED_HOSTS` and browser origins through `MCP_ALLOWED_ORIGINS`; do not disable the protection to make a proxy work.

Internal network reachability is not authorization. Keep these services unpublished unless the calling deployment provides its own authenticated control plane.

## External or tenant-crossing deployments

Set all of the following explicitly:

```text
MCP_TRUST_BOUNDARY=external
MCP_PUBLIC_URL=https://mcp.example.test/mcp
MCP_AUTH_TOKEN=<runtime secret>
MCP_ALLOWED_HOSTS=mcp.example.test,mcp.example.test:*
MCP_ALLOWED_ORIGINS=https://trusted-ui.example.test
```

External mode fails closed if `MCP_PUBLIC_URL` or `MCP_AUTH_TOKEN` is missing, and non-loopback external URLs must use HTTPS. The configured bearer token is only verified server-side and is never returned by an MCP tool. `MCP_ISSUER_URL` may be supplied when the authorization issuer differs from the resource URL.

For multi-user/public deployments, prefer a real OAuth/OIDC verifier at the gateway or replace the static resource-server token with an identity-aware verifier rather than sharing one token across tenants.

## Traxx credential destination policy

Traxx service tokens, actor tokens and proxy/WAF headers are credential-bearing state. `configure_traxx` therefore cannot move an already configured/credentialed connector to an arbitrary origin. The initial `TRAXX_URL` origin is trusted automatically; additional migration targets must be pre-approved by the operator with comma-separated `TRAXX_ALLOWED_ORIGINS`.

A completely unconfigured and credential-free connector may choose its first origin. After that origin or any credential exists, an origin change without an operator allowlist is rejected. Base URLs must be bare HTTP(S) origins and may not contain URL userinfo, application paths, queries, or fragments.

TLS verification is on by default. Persisting or using `verify_tls=false` is rejected unless the deployment explicitly sets `TRAXX_ALLOW_INSECURE_TLS=true`; that switch is intended only for isolated development/test environments.

## Proxy headers

Host validation uses the actual HTTP `Host` header reaching FastMCP. Do not trust arbitrary `Forwarded` or `X-Forwarded-Host` values to expand the MCP allowlist. A reverse proxy should normalize the upstream Host header to one of the explicitly configured values and terminate TLS before forwarding into the private service network.
