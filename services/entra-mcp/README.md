# Microsoft Entra MCP

`entra-mcp` is a product-neutral, bounded, read-only MCP service for Microsoft Entra ID diagnostics through Microsoft Graph. It is designed for administrators and agent orchestration without exposing arbitrary Graph access.

## Safety model

The service uses OAuth 2.0 client credentials with a dedicated app registration and fixed Microsoft cloud endpoints. Startup fails unless `ENTRA_BACKEND_READ_ONLY=true` is explicitly asserted and tenant/client GUIDs plus a client secret are configured. Resource operations use GET only. The MCP exposes no arbitrary Graph path, OData filter/search/expand/order expression, delegated user context, raw Graph payload, or write operation.

Every collection is bounded by page/sample limits, request timeout, response-byte limit, concurrency and rate limits, plus a per-tool query budget for request count, returned items, bytes, fan-out and total time. Microsoft Graph `@odata.nextLink` values are accepted only as opaque cursors after binding them to the same configured Graph origin, fixed endpoint and fixed `$select` projection; only `$skiptoken`, `$select` and `$top` are accepted.

## Observe surface

The initial contract includes tenant organization details, users, groups, devices, applications, service principals, activated directory roles, Conditional Access policies and an aggregate diagnostic bundle. Returned records are projected to a fixed field allowlist and nested secret-shaped values are redacted before they reach the agent.

## Least-privilege application permissions

Use resource-specific read permissions rather than broad `Directory.Read.All` wherever possible. The current fixed surface is designed for `Organization.Read.All`, `User.Read.All`, `Group.Read.All`, `Device.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory` and `Policy.Read.All`. `Group.Read.All` is intentionally used for group inventory because it remains read-only even where Microsoft's current group-list permission table exposes a specialized permission with a read/write name as the nominal least-privileged option.

Grant only the permissions needed for the tools you deploy. The public package does not contain tenant IDs, client IDs, internal naming conventions, group names, Conditional Access policy names or organization-specific topology.

## Cloud support

`ENTRA_CLOUD` is a closed enum: `global`, `usgov`, `dod` or `china`. Authority and Graph origins are selected from built-in mappings, which prevents deployment configuration from turning the connector into an arbitrary HTTP proxy.

## Authentication and secret handling

Store `ENTRA_CLIENT_SECRET` in runtime secret storage. The access token is cached in process until shortly before expiry to avoid unnecessary token requests. Neither the client secret nor access token is returned through capabilities, audit metadata or observations.

## Development

Install `mcp-common` and this service with the repository Python lock, then run Ruff, Pytest and `compileall`. The dedicated workflow also builds the non-root production container. A real-tenant integration test is intentionally outside public CI because CI must not depend on organization credentials.
