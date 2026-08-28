# n8n MCP

`n8n-mcp` is a product-neutral, bounded **read-only** diagnostics adapter for the n8n Public API. It is intended for administrators and AI agents that need workflow inventory and execution health without receiving workflow definitions, node parameters, credential values, execution payloads, or a generic n8n API proxy.

## Safety model

The service exposes only fixed `GET` operations for workflow inventory, execution inventory, and one exact execution. `N8N_BACKEND_READ_ONLY=true` is an explicit deployment attestation and the API key should belong to a dedicated identity with the narrowest available read scopes. Enterprise deployments should scope the key to workflow/execution reads where supported; other deployments should use a dedicated n8n user whose accessible workflows are intentionally limited.

The MCP does **not** use `projectId` as an authorization boundary. Use the API identity plus optional `N8N_ALLOWED_WORKFLOW_IDS`. When a workflow allowlist is configured, execution list/get operations require an explicit allowlisted `workflow_id`, and every returned execution is verified against that workflow before it can leave the adapter.

All backend calls use the shared `mcp-common` read-only connector and query-budget controls: fixed operation allowlisting, pagination caps, response-byte caps, timeout, rate limit, concurrency limit, sampling, per-tool request/item/fan-out budgets, audit envelopes, and correlation IDs. Redirects and caller-selected URLs or methods are rejected.

## Exposed observations

`n8n_list_workflows` returns only safe workflow metadata: ID, name, active/archive state, timestamps, and bounded tag metadata. It deliberately discards nodes, connections, settings, static data, pinned data, and any credential references present in the upstream response.

`n8n_list_executions` always sends `includeData=false` and returns only bounded execution metadata such as execution/workflow IDs, state, mode, timestamps, retry linkage, and completion state. `n8n_get_execution` does the same for an exact execution. `n8n_diagnostic_bundle` performs aggregate-first workflow/execution observation and derives a status summary locally instead of fanning out across every workflow.

There are no workflow trigger, activation, retry, stop, create, update, delete, credential, variable, project, arbitrary REST, or generic HTTP tools in Observe v1.

## Configuration

Set `N8N_API_BASE_URL` to the deployment-owned Public API base ending in `/api/v1`, for example `https://n8n.example.invalid/api/v1`. Put the API key only in `N8N_API_KEY`; never encode credentials in the URL. Plain HTTP is fail-closed unless `N8N_ALLOW_INSECURE_HTTP=true` is deliberately set for a protected lab network.

Set `N8N_BACKEND_READ_ONLY=true` only after the dedicated API identity has been reviewed. Optionally configure comma-separated exact IDs in `N8N_ALLOWED_WORKFLOW_IDS` to add a second egress boundary independent of n8n project filtering.

The `.env.example` documents bounded defaults. Public repository files intentionally contain no company topology, credentials, project IDs, workflow IDs, tenant information, or internal policy.

## Running

Install `packages/mcp-common`, then this package, and start `mcp-n8n`. For containers, build from repository root with `services/n8n-mcp/Dockerfile`. The example Compose service runs as a non-root user with a read-only filesystem, dropped capabilities, and loopback-only port publishing.

## Write operations

Observe v1 contains no writes. Future changes must use a separate `plan -> approval -> change -> verify` surface with typed pre-state, idempotency and rollback information where the n8n API makes that safely possible. A read-only backend connection remains supported even if a future write layer exists.
