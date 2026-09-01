# Checkmk MCP

Production-oriented, product-neutral **Observe v1** diagnostics for Checkmk monitoring through the stable REST API at `/check_mk/api/1.0`.

The contract was verified on 2026-09-01 against the current Checkmk 2.5 documentation and vendor source. Checkmk 2.5.0 is the currently maintained stable generation. Checkmk 3.0 beta also contains a vendor MCP server, but that feature is explicitly experimental; this service therefore does not depend on the 3.0 beta MCP surface for production deployments.

## Fail-closed deployment

Use a dedicated Checkmk automation user with a deployment-owned role derived from the narrowest permissions required to read monitoring state. Checkmk automation users have normal role and contact semantics, so deployments can restrict both permissions and host/service visibility through roles and contact groups.

The adapter requires all of:

- `CHECKMK_BACKEND_READ_ONLY=true`;
- a non-empty `CHECKMK_BACKEND_ROLE` attestation;
- `CHECKMK_API_BASE_URL` ending in the stable `/check_mk/api/1.0` root;
- a dedicated `CHECKMK_USERNAME` and `CHECKMK_AUTOMATION_SECRET`;
- HTTPS unless insecure HTTP is explicitly enabled for a controlled lab deployment.

The backend role name is deployment-owned rather than hard-coded because Checkmk supports custom roles and site-specific contact scoping. Do not use an administrator account merely to satisfy this MCP.

Bearer authentication follows the vendor-supported automation-user form and is sent only in the HTTP `Authorization` header. Redirects are disabled so credentials are never forwarded to another origin by the client.

## Observe v1 tools

The public MCP surface is deliberately small:

- `checkmk_get_version`: bounded REST API/version observation.
- `checkmk_list_problem_hosts`: only monitored hosts whose state is not UP.
- `checkmk_list_problem_services`: only monitored services whose state is not OK.
- `checkmk_list_host_problem_services`: bounded problem-service drill-down for one validated host identifier.
- `checkmk_diagnostic_bundle`: aggregate-first version, problem-host and problem-service evidence with explicit truncation semantics.

The host/service monitoring endpoints use the vendor-supported POST form introduced to replace the deprecated GET query form. The MCP internally generates the Livestatus query object and the fixed column list. Callers cannot submit Livestatus expressions, columns, API paths, HTTP methods or arbitrary request bodies.

The projection intentionally excludes host addresses, contacts/contact groups, labels/tags, plugin output, performance data, comments, acknowledger/comment text and other unrestricted monitoring payloads. State, bounded object identity, acknowledgment/downtime/flapping/stale flags and timestamps are sufficient for agent triage without streaming the full monitoring dataset.

## Query and server-load safety

`mcp-common` `ReadOnlyConnector` and `QueryBudget` enforce request, item, response-byte, concurrency, rate, elapsed-time and fan-out budgets. Observe v1 queries server-side for problem objects before sampling. The upstream REST endpoint does not provide a cursor contract suitable for this strict adapter, so this MCP deliberately exposes no page cursor: each request is bounded and any result beyond the requested limit is represented as `truncated=true` rather than enabling agents to crawl the entire monitoring estate automatically.

The diagnostic bundle runs aggregate-first and does not fan out per host. Returned problem counts are exact only when the associated result is not truncated; otherwise they are documented lower bounds for that request.

## Explicitly not exposed

Observe v1 contains no:

- Setup/configuration endpoint;
- activation, discovery, agent registration or configuration change;
- downtime, acknowledgment, notification or master-control mutation;
- arbitrary REST proxy or Livestatus/query DSL;
- arbitrary host/service inventory export;
- raw plugin output, perfdata, comments, contacts or address data;
- use of `/api/unstable` endpoints.

Any future state-changing capability must use a separate least-privilege identity and the repository `plan -> approval -> change -> verify` lifecycle with idempotency, pre-state and rollback declaration where feasible.

## Primary vendor references

- Checkmk REST API: https://docs.checkmk.com/latest/en/rest_api.html
- Checkmk users, roles and permissions: https://docs.checkmk.com/latest/en/wato_user.html
- Host monitoring POST change: https://checkmk.com/werk/17003
- Service monitoring POST change: https://checkmk.com/werk/17512
- Checkmk 3.0 beta MCP is experimental: https://checkmk.com/werk/22263
