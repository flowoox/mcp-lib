# UniFi Network Diagnostics MCP

`unifi-mcp` is a product-neutral, bounded **read-only** MCP adapter for Ubiquiti's official UniFi Network Integration API. It intentionally does not use the legacy private controller/session API.

## Observe v1 surface

The service exposes fixed observations for application version, local sites, adopted devices, latest per-device statistics, connected clients, and an aggregate-first site diagnostic bundle. The bundle lists device/client health once and does not fan out into statistics for every device.

The public projection deliberately omits device/client MAC and IP addresses, client names, configuration identifiers, arbitrary raw API payloads, and all configuration/action endpoints. UniFi's API filter DSL is not exposed.

## Backend and least privilege

Set `UNIFI_BACKEND_READ_ONLY=true` only after the deployment has created the API key from a UniFi identity/role whose permissions are restricted to the intended read-only sites. The flag is an explicit fail-closed attestation, not a privilege escalation workaround. The API key remains deployment-owned and is never returned by MCP tools.

`UNIFI_API_BASE_URL` must point at an official Network Integration API base ending in `/proxy/network/integration`, for example a local console or the documented UniFi cloud connector. URLs, console IDs, credentials, sites, network topology, and company policy do not belong in this public repository.

Local consoles often use private PKI. Prefer deploying the issuing CA into the container and keeping `UNIFI_TLS_VERIFY=true`; only disable verification for a controlled lab.

## Safety controls

- GET-only fixed operation allowlist; no arbitrary URL/method proxy
- no API `filter` parameter exposed to agents
- `offset`/`limit` pagination bounded by the configured maximum offset/page size
- request, item, byte, elapsed-time, fan-out, concurrency, and rate budgets
- redirects rejected; response bytes capped before JSON parsing
- HTTP 429 is surfaced without automatic retries
- audit reason and correlation ID on every observation
- read-only backend attestation required at startup
- container runs non-root with a read-only filesystem example

Any future configuration or action capability must be a separate write layer with a separate least-privilege identity and `plan -> approval -> change -> verify`, idempotency, pre-state, and rollback semantics. Observe v1 will not grow a generic action proxy.

## Tools

- `get_capabilities`
- `unifi_get_application_info`
- `unifi_list_sites`
- `unifi_list_devices`
- `unifi_get_device`
- `unifi_get_device_statistics`
- `unifi_list_clients`
- `unifi_get_client`
- `unifi_site_diagnostic_bundle`

## Development

```bash
python -m pip install -e "services/unifi-mcp[dev]"
ruff check services/unifi-mcp/src services/unifi-mcp/tests
pytest -q services/unifi-mcp/tests
python -m compileall -q services/unifi-mcp/src
```
