# Veeam MCP

Product-neutral, bounded **read-only** diagnostics for the Veeam Backup & Replication 13 REST API. Observe v1 is pinned to the vendor-documented `1.3-rev2` contract and requires a deployment-managed identity assigned the built-in **Backup Viewer** role.

## Observe surface

- job states (`GET /api/v1/jobs/states`)
- recent sessions (`GET /api/v1/sessions`)
- repository states/capacity health (`GET /api/v1/backupInfrastructure/repositories/states`)
- backup inventory (`GET /api/v1/backups`)
- restore-point health with a hard history window (`GET /api/v1/restorePoints`)
- aggregate-first diagnostic bundle over the above bounded lists

Authentication uses only the exact VBR OAuth token endpoint (`POST /api/oauth2/token`). That authentication request is not exposed as an MCP operation. Resource observations are fixed GET routes only; redirects, arbitrary paths, generic filter DSLs and caller-selected HTTP methods are rejected.

## Fail-closed deployment

Set `VEEAM_BACKEND_READ_ONLY=true` and `VEEAM_BACKEND_ROLE=Backup Viewer`. These values are explicit deployment attestations: the service refuses to construct its transport without both. Do not use Backup Administrator/Operator credentials for Observe v1. Credentials and topology stay in deployment configuration and are never included in capabilities metadata.

Repository host names and paths, session initiators and result messages, credential inventory, job start/stop, restore, export, rescan and configuration endpoints are intentionally excluded. Query budgets cap requests, rows, response bytes, concurrency, fan-out and total execution time.

See `.env.example` for deployment values and `docs/infrastructure/veeam-mcp-observe-v1.json` for the machine-readable contract evidence.
