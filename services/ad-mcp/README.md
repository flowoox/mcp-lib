# Active Directory MCP

Product-neutral Microsoft Active Directory diagnostics plus narrowly controlled lifecycle operations for MCP clients.

The service is intentionally **not** a generic PowerShell bridge. Every upstream operation is a repository-owned script selected from a fixed allowlist. Tool input is validated and serialized as JSON into a dedicated environment variable; it is never interpolated into PowerShell source, and the process is launched with `shell=False`.

## Capabilities

Read-only capabilities:

- domain/forest, FSMO and domain-controller summary
- replication failure and partner metadata
- AD LDAP/Kerberos SRV DNS discovery checks
- local member-computer secure-channel test (no repair)
- domain security-baseline evidence and findings
- bounded user lookup
- direct user group-membership inventory
- bounded computer lookup
- bounded group lookup
- bounded organizational-unit inventory

Controlled lifecycle capabilities:

- plan/change/verify one user's enabled state
- plan/change/verify one user's direct membership in one AD group

Write operations are high-risk capabilities. They are disabled by default, require idempotency keys, capture pre-state in their plan, declare rollback intent, require a short-lived signed out-of-band approval grant, and independently read AD back after mutation.

## Runtime

This service is Windows-native because it uses Microsoft's `ActiveDirectory` PowerShell module rather than embedding credentials in a cross-platform LDAP client.

Requirements:

1. Windows Server or a supported Windows management host.
2. PowerShell (`powershell.exe` or `pwsh.exe`).
3. RSAT Active Directory PowerShell module.
4. A dedicated service identity with only the directory rights required by the enabled tools.

For read-only deployments, grant only directory read rights. When writes are explicitly enabled, delegate only the exact OUs/groups that the service is allowed to administer instead of running the process as Domain Admin. Credentials are inherited from the service process; MCP tools do not accept usernames or passwords.

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
| `AD_WRITES_ENABLED` | `false` | Explicitly enable registered AD mutation tools |
| `AD_APPROVAL_SECRET` | empty | HMAC secret used only to verify signed approval grants; minimum 32 bytes when writes are enabled |

`AD_POWERSHELL_EXECUTABLE` is fail-closed to PowerShell/pwsh basenames. Pointing it at `cmd.exe`, a shell wrapper or another interpreter is rejected. `AD_WRITES_ENABLED=true` without a sufficiently strong approval secret fails service startup.

## Approval boundary

The MCP service never mints its own approval. A separate trusted workflow (for example n8n behind an operator approval step, a ticketing integration, or a policy service) signs an approval grant with `mcp_common.approval_grants.issue_approval_grant`.

A grant is bound to exactly:

- one operation ID;
- one target string;
- one idempotency key;
- the non-secret desired-state intent reviewed by the approver (stored as a canonical SHA-256 digest);
- an approver and reason;
- a short validity window (maximum one hour).

The service verifies the HMAC signature and every binding before running a mutation. Reusing a grant for another user, group, operation, idempotency key, **or opposite desired state** is rejected. For example, a grant approving `enabled=true` cannot be reused to disable the same account. The signing secret stays in the trusted approval workflow and the AD MCP verifier; it is never returned by an MCP tool. The opaque grant itself is not included in operation output or audit metadata.

Every plan returns an `approvalBinding` object. Use that exact operation, target, idempotency key and intent when minting the grant rather than rebuilding them from organization-specific logic.

Example approval data for enabling `alice`:

```text
operation: ad.user.enabled.change
target: user:alice
idempotency_key: joiner/alice/enable
intent: {"enabled": true}
```

Example approval data for adding `alice` to `VPN-Users`:

```text
operation: ad.user.group-membership.change
target: user:alice|group:VPN-Users
idempotency_key: joiner/alice/vpn-membership
intent: {"present": true}
```

Organization-specific mappings and approval policy do not belong in this public repository.

## Plan -> change -> verify

The intended flow is:

```text
observe current state
        |
        v
plan mutation + capture pre-state + exact approvalBinding
        |
        v
external approval workflow signs exact plan identity + desired state
        |
        v
change tool verifies grant + applies target state
        |
        v
independent AD readback verification
```

The change scripts are target-state idempotent: enabling an already enabled user or adding an already present direct membership returns `changed=false`. The idempotency key is still mandatory and is included in operation/audit context. Invalid idempotency keys are rejected before any AD mutation command executes. Verification is performed through a separate read probe rather than trusting the mutation command's return value.

## DNS and inventory bounds

`dns_discovery` resolves only the domain-derived LDAP and Kerberos SRV names used for AD service discovery. It does not accept arbitrary DNS names. `list_organizational_units` exposes only a numeric result limit, validated to 1-1000; callers cannot supply an LDAP filter or arbitrary PowerShell expression.

## Security baseline

`security_baseline` reads evidence from the default domain password policy and directory configuration and evaluates it in Python. Default thresholds are deliberately visible and caller-overridable:

- minimum password length: 14
- password history: 24
- maximum lockout threshold: 10
- machine-account quota: 0

It also flags disabled complexity, reversible password encryption, disabled lockout, disabled AD Recycle Bin and legacy domain functional levels. Findings are guidance, not automatic remediation. Organizations should select thresholds that match their authoritative security policy and compatibility requirements.

## Correlation and audit

Every response uses the shared `mcp_common.operations` envelope. A caller may supply a UUID correlation ID to connect multiple probes in one incident or orchestration. State-changing operations also require a distinct idempotency key.

The current `actor` value identifies the MCP client boundary, not a cryptographically authoritative human identity. Human approval identity is carried separately in the signed approval grant. Deployments should additionally connect authenticated MCP client identity and operation audit events to an authoritative audit sink.

## Deliberate non-capabilities

This release does not expose arbitrary PowerShell, LDAP filters, user creation, password setting/reset, OU moves, GPO modification, replication repair, secure-channel repair, group creation/deletion, or bulk mutation. Those require separate narrowly scoped contracts and tests before they are eligible for inclusion.
