# Active Directory MCP

Product-neutral, read-only Microsoft Active Directory diagnostics for MCP clients.

The service is intentionally **not** a generic PowerShell bridge. Every upstream operation is a repository-owned script selected from a fixed allowlist. Tool input is validated and serialized as JSON into a dedicated environment variable; it is never interpolated into PowerShell source, and the process is launched with `shell=False`.

## Initial capabilities

- domain/forest, FSMO and domain-controller summary
- replication failure and partner metadata
- local member-computer secure-channel test (no repair)
- domain security-baseline evidence and findings
- bounded user lookup
- bounded computer lookup
- bounded group lookup

All v1.0 capabilities are `observe` / `read_only`. There are no directory mutation tools in this release.

## Runtime

This service is Windows-native because it uses Microsoft's `ActiveDirectory` PowerShell module rather than embedding credentials in a cross-platform LDAP client.

Requirements:

1. Windows Server or a supported Windows management host.
2. PowerShell (`powershell.exe` or `pwsh.exe`).
3. RSAT Active Directory PowerShell module.
4. A domain identity with only the read rights required by the enabled probes.

Run the MCP process under a dedicated service identity or gMSA where possible. Do not run it as Domain Admin simply to make diagnostics convenient. Credentials are inherited from the service process; MCP tools do not accept usernames or passwords.

Example install from the repository root:

```powershell
py -3.12 -m pip install --constraint constraints/python312.lock ./packages/mcp-common
py -3.12 -m pip install --constraint constraints/python312.lock -e ".\services\ad-mcp[dev]"
mcp-ad
```

The default listener is `127.0.0.1:8084`. Use the shared MCP trust-boundary settings (`MCP_TRUST_BOUNDARY`, `MCP_PUBLIC_URL`, `MCP_AUTH_TOKEN`, allowed hosts/origins) before exposing the service beyond localhost.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MCP_HOST` | `127.0.0.1` | MCP listener address |
| `MCP_PORT` | `8084` | MCP listener port |
| `MCP_TRUST_BOUNDARY` | `internal` | Shared internal/external trust mode |
| `AD_POWERSHELL_EXECUTABLE` | `powershell.exe` | Allowed PowerShell executable |
| `AD_COMMAND_TIMEOUT_SECONDS` | `30` | Per-probe execution timeout (3-180s) |

`AD_POWERSHELL_EXECUTABLE` is fail-closed to PowerShell/pwsh basenames. Pointing it at `cmd.exe`, a shell wrapper or another interpreter is rejected.

## Security baseline

`security_baseline` reads evidence from the default domain password policy and directory configuration and evaluates it in Python. Default thresholds are deliberately visible and caller-overridable:

- minimum password length: 14
- password history: 24
- maximum lockout threshold: 10
- machine-account quota: 0

It also flags disabled complexity, reversible password encryption, disabled lockout, disabled AD Recycle Bin and legacy domain functional levels. Findings are guidance, not automatic remediation. Organizations should select thresholds that match their authoritative security policy and compatibility requirements.

## Correlation and audit

Every diagnostic response uses the shared `mcp_common.operations` envelope. A caller may supply a UUID correlation ID to connect multiple probes in one incident or orchestration. The response includes a structured read-only audit event with the same correlation ID.

The current `actor` value identifies the MCP client boundary, not a cryptographically authoritative human identity. Deployments that require per-human attribution should connect authenticated client identity to an audit sink before enabling future write capabilities.

## Planned write layer

Directory changes will be introduced separately using `plan -> approval -> change -> verify`. They must include idempotency keys, pre-state and rollback metadata where feasible, and will remain disabled until their tests and approval boundary are complete. No future write tool should accept arbitrary PowerShell.
