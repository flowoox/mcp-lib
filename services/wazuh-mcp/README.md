# Wazuh MCP

Production-oriented, product-neutral **Observe v1** diagnostics for Wazuh. The service exposes a small typed MCP surface over two deliberately separate read-only backends:

- the Wazuh server API for API/manager/agent health, using the built-in `readonly` RBAC role;
- the Wazuh indexer API for **aggregation-only** alert and vulnerability summaries, using a deployment-owned read-only indexer role.

The contract was verified against the current Wazuh **4.14.7** server API. Wazuh 4.14.7 was released on 2026-07-29. Deployment URLs, credentials, certificates, topology and organization policy remain external configuration.

## Fail-closed deployment

The server-side reader requires all of:

- `WAZUH_SERVER_BACKEND_READ_ONLY=true`
- `WAZUH_SERVER_BACKEND_ROLE=readonly`
- an explicit server API URL and dedicated credentials.

Authentication is the one fixed internal write-shaped request required by Wazuh: `POST /security/user/authenticate?raw=true` with Basic Auth obtains a JWT. Every observation after that is a fixed GET operation. The MCP never exposes the authentication call as a tool.

The indexer-side reader requires:

- `WAZUH_INDEXER_BACKEND_READ_ONLY=true`
- a non-empty deployment-owned role attestation;
- a dedicated indexer API URL and credentials.

For the indexer identity, create the narrowest supported role: read-only cluster permission such as `cluster_composite_ops_ro` and `read` only for `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`. Do not grant index management, document write/delete, security administration or broad `*` index access merely for this MCP.

## Observe v1 tools

The public tool surface is intentionally bounded:

- `wazuh_get_health_summary`: API version, aggregate agent status, manager daemon state and summarized manager log counters.
- `wazuh_list_agents`: bounded/paginated agent inventory with a fixed connection-status filter.
- `wazuh_get_alert_summary`: server-side index aggregation by Wazuh rule level in a bounded time window.
- `wazuh_get_vulnerability_summary`: current vulnerability-state counts by severity plus maximum CVSS base score.
- `wazuh_diagnostic_bundle`: aggregate-first agent/manager/alert/vulnerability health without per-agent fan-out.

Agent IPs, enrollment addresses/keys, groups, manager assignment, raw alert documents, raw vulnerability/CVE/package documents and manager log messages are not returned.

## Query safety

`mcp-common` `ReadOnlyConnector` and `QueryBudget` enforce page/sample limits, response-byte ceilings, request budgets, concurrency, rate limits, total runtime and aggregate-before-fan-out. The alert window is capped by `WAZUH_MAX_ALERT_WINDOW_MINUTES` and callers cannot provide arbitrary WQL, URL paths, index names or OpenSearch DSL.

Observe v1 deliberately has no active-response tool, agent enrollment/removal/upgrade/restart, manager restart, configuration write, security/RBAC mutation, arbitrary index query, index mutation or raw document export.

The older Wazuh server vulnerability endpoints are not used. Current vulnerability state is read through the Wazuh indexer `wazuh-states-vulnerabilities-*` indices, matching current Wazuh architecture.

## Primary vendor references

- Wazuh server API reference 4.14.7: https://documentation.wazuh.com/current/user-manual/api/reference.html
- Wazuh server API RBAC: https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html
- Wazuh indexer API use cases: https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html
- Wazuh indexer user/role administration: https://documentation.wazuh.com/current/user-manual/user-administration/wazuh-indexer.html
- Wazuh indexer indices: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- Wazuh release notes: https://documentation.wazuh.com/current/release-notes/index.html
