# ManageEngine MDM MCP

Product-neutral, bounded **read-only** diagnostics for ManageEngine Mobile Device Manager Plus. This service intentionally exposes only a small fixed REST v1 GET surface and uses the shared `ReadOnlyConnector`, `QueryBudget`, audit/correlation and MCP transport-security controls.

## Observe v1

Tools provide:

- bounded/sampled managed-device inventory with optional platform and free-text search;
- exact last scan status for a selected device;
- bounded command history for 1-30 days;
- an aggregate-first diagnostic bundle combining scan status and recent command outcomes.

The public projection intentionally excludes IMEI, serial number, UDID, SIM identifiers, assigned-user name/e-mail, locations, firmware/FileVault secrets, APN credentials and command-initiator identity. The adapter never exposes the raw device-details endpoint because that response can contain secrets and high-sensitivity identifiers even though it is a GET.

## Backend identity

The deployment must provide a dedicated least-privilege reader and explicitly attest it with `MDM_BACKEND_READ_ONLY=true`; startup fails closed otherwise.

- **ManageEngine MDM Cloud:** OAuth bearer token with only `MDMOnDemand.MDMInventory.READ` for this v1 surface. The adapter sends `Authorization: Zoho-oauthtoken <token>`.
- **On-premises:** dedicated API key/role restricted to `MDMInventory.READ`. The adapter sends the API key in `Authorization`.

Do not grant device-management CREATE/UPDATE/DELETE permissions to this service identity. `MDM_API_BASE_URL`, token, optional customer ID, TLS trust and all tenant-specific policy remain deployment-owned and are never committed.

## Safety boundary

The transport accepts only these internal operations:

- `manageengine_mdm.devices.list` -> `GET /api/v1/mdm/devices` with fixed `summary=true`, bounded pagination and allowlisted filters;
- `manageengine_mdm.devices.scan_status` -> `GET /api/v1/mdm/devices/{device_id}/actions/scan`;
- `manageengine_mdm.devices.command_history` -> `GET /api/v1/mdm/devices/{device_id}/commandhistory` with bounded pagination and 1-30 day lookback.

There is no generic URL/method proxy, caller-controlled HTTP method, location lookup, firmware-password access, device action, profile/app mutation, wipe/lock, command initiation, arbitrary search-field selection or raw-response passthrough. Pagination links returned by the server are never followed: only a validated offset/skip token is extracted and replayed against the same fixed endpoint.

## Agent load protection

Defaults are intentionally conservative: page limit 100, response limit 2 MiB, two concurrent upstream calls, two requests/second and a per-tool query budget for requests/items/bytes/fan-out/elapsed time. Sampling happens after raw cost accounting. The diagnostic bundle performs two bounded exact-device reads rather than fleet fan-out.

## Run

Copy `.env.example` to a deployment-owned environment file and configure the endpoint/read-only identity. For local testing:

```bash
python -m pip install -e "services/manageengine-mdm-mcp[dev]"
pytest -q services/manageengine-mdm-mcp/tests
mcp-manageengine-mdm
```

The container runs as UID/GID 10001 and the example Compose deployment drops Linux capabilities and makes the root filesystem read-only.
