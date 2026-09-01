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

Set `VEEAM_BACKEND_READ_ONLY=true`, `VEEAM_BACKEND_ROLE=Backup Viewer` and `VEEAM_BACKEND_BUILD=<verified-build>`. The service rejects a configured backend when the build attestation is absent, malformed, not VBR 13, or lower than **13.0.1.2067**. This floor protects the Backup Viewer trust assumption tracked by SEC-042; use a current supported patched VBR 13 train after normal compatibility/change validation rather than treating the minimum floor as the preferred long-term target.

`GET /api/v1/serverInfo` exposes the authoritative VBR build but Veeam documents that endpoint as **Backup Administrator** only. Observe v1 deliberately does not elevate its runtime identity merely to read version metadata. Verify the real backend build through an administrator-controlled operational check/change record and inject only the non-secret build number as `VEEAM_BACKEND_BUILD`. If Veeam later exposes a stable Backup-Viewer-readable build endpoint, prefer a fail-closed automatic preflight without widening the MCP capability surface.

The role/build values are deployment attestations; credentials and topology stay in deployment configuration and are never included in capabilities metadata. Do not use Backup Administrator/Operator credentials for Observe v1.

Repository host names and paths, session initiators and result messages, credential inventory, job start/stop, restore, export, rescan and configuration endpoints are intentionally excluded. Query budgets cap requests, rows, response bytes, concurrency, fan-out and total execution time.

See `.env.example` for deployment values and `docs/infrastructure/veeam-mcp-observe-v1.json` for the machine-readable contract evidence.
