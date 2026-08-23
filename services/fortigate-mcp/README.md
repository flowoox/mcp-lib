# FortiGate MCP

`fortigate-mcp` is a product-neutral infrastructure MCP for bounded FortiGate observation. The initial release is intentionally read-only and exposes only fixed GET operations against allowlisted FortiOS REST API endpoints.

## Safety model

The backend identity must be a dedicated FortiOS REST API administrator with read-only permissions. Startup fails unless `FORTIGATE_BACKEND_READ_ONLY=true` is explicitly asserted, an API token is present, the base URL is a bare HTTPS origin, and TLS verification is enabled unless an explicit insecure-test override is configured. The service never exposes arbitrary API paths, HTTP methods, filters, format expressions, CLI commands, raw configuration payloads, or write tools.

VDOM access is constrained by `FORTIGATE_ALLOWED_VDOMS`. Every collection request has a page limit, optional bounded sampling, response-byte limit, rate limit, concurrency cap and a per-tool query budget. The adapter requests only a fixed field projection for CMDB tables and then projects the response again before returning it to an agent.

## Observe tools

The contract currently provides system and HA observation, interface inventory, static routes, IPv4 firewall policies, firewall address objects, IPsec phase1-interface inventory, and an aggregate diagnostic bundle. All responses carry the common `OperationResult` and `AuditEvent` envelopes with actor, reason and correlation ID while excluding credentials from audit metadata.

## Configuration

Copy `.env.example` into deployment-specific configuration and supply the FortiGate URL, token, allowed VDOMs and MCP trust-boundary settings externally. Do not commit real appliance addresses, tokens, VDOM names, internal topology or organization-specific policies to this repository.

For production, install a CA bundle when the appliance certificate is issued by a private PKI. `FORTIGATE_ALLOW_INSECURE_TLS=true` exists only as an explicit lab override and should remain disabled in production.

## Backend permissions

Create a dedicated REST API administrator whose access profile permits GET/read access only to the system, interface, router, firewall and VPN data required by this service. Fortinet recommends read permissions when an API account is used only for retrieving statistics or information. Trusted-host restrictions should also limit the API administrator to the MCP connector hosts.

## Development

From the repository root, install `mcp-common` and the service in editable mode, then run Ruff, Pytest and `compileall`. The repository CI also validates the locked dependency graph. A path-scoped workflow builds the container to ensure the production entrypoint remains installable.
