# Infrastructure MCP architecture

This document defines the public, product-neutral architecture for infrastructure MCP services in `mcp-lib`.

## Design goal

Infrastructure MCPs expose narrow, typed, auditable capabilities for diagnostics and controlled administration. They are not arbitrary shell, PowerShell, SQL, or provider-API proxies.

Every capability follows the same lifecycle:

```text
observe -> plan -> change -> verify
```

`observe` is read-only. `plan` captures the intended target state, risk, pre-state and rollback. `change` performs only an explicitly registered mutation. `verify` proves the requested post-condition independently of the mutation call.

The shared models in `mcp_common.operations` provide correlation IDs, actor/source context, idempotency keys, approval state, risk classification, rollback metadata, verification results and structured audit envelopes.

## Security invariants

- Tool registration is explicit; no arbitrary command execution primitive is exposed.
- Inputs are typed and reject unknown fields.
- Credentials are runtime configuration and must never be returned in MCP output or audit metadata.
- Network reachability is not authorization.
- State-changing plans require an idempotency key.
- High and critical risk tools require an approval gate.
- Reversible plan steps declare their rollback action before execution.
- Pre-state is captured before mutation where the upstream API permits it.
- Read-only tools cannot report mutation success.
- Observe services support a separately provisioned read-only backend connection and fail closed
  unless the adapter declares that mode; an optional write identity belongs behind a distinct,
  disabled-by-default plan/change/verify layer.
- Agent-facing diagnostics use per-invocation query budgets, bounded pagination and sampling,
  response-size limits, timeouts, rate limits, concurrency caps and aggregation before fan-out.
- External MCP endpoints reuse the existing `mcp_common.mcp_security` trust-boundary controls.

Approval is an interface boundary, not a hard-coded business workflow. Deployments may connect it to n8n, an agent policy engine, a ticket system, or another authoritative approval source.

The concrete provider adapter remains responsible for enforcing a raw response byte limit while
streaming and for mapping its typed operation allowlist to fixed upstream methods and paths. The
shared `mcp_common.read_only_connector` boundary never accepts a caller-selected URL, HTTP method,
SQL statement or shell command. See [`QUERY-SAFETY.md`](QUERY-SAFETY.md).

## Service sequence

The implementation order is dependency-driven:

1. `mcp-common` operation, policy, approval and audit contracts.
2. `ad-mcp` for Active Directory diagnostics and controlled directory changes.
3. `network-mcp` for DNS, routes, reachability and path diagnostics.
4. `fortigate-mcp` for FortiGate/FortiManager inventory, analysis and controlled policy changes.
5. `entra-mcp` for Microsoft Graph / Entra ID inventory, security posture and controlled changes.
6. `windows-mcp` for Windows Server diagnostics.
7. `security-audit-mcp` for cross-service findings and baseline evaluation.
8. Additional reusable services such as UniFi, Veeam, Hyper-V, Wazuh, Checkmk, PKI and Exchange/M365.

Vendor clients remain behind narrow service-specific adapters. Cross-service product/business workflows do not belong in the public MCP service implementation.

## Employee-entry reference workflow

The employee-entry process is a reference orchestration, not a privileged monolithic MCP:

```text
validated joiner request
        |
        v
AD plan/change/verify
        |
        v
Entra/M365 plan/change/verify
        |
        v
network/VPN/device entitlements
        |
        v
cross-service verification + audit record
```

An orchestrator such as n8n or an agent supplies one correlation ID across the workflow and a distinct idempotency key per mutation. The orchestrator stores organization-specific OU paths, group mappings, licensing policy, network topology and approval rules outside this public repository.

## Contract compatibility

The shared operation models are provider-neutral infrastructure building blocks. Service contracts should expose their own versioned capability family while embedding these shared envelopes. Additive fields remain backwards compatible within a contract major; semantic changes require a new major.

## Required test classes

Each infrastructure service must include:

- contract/capability tests;
- allow tests for explicitly supported operations;
- deny tests proving arbitrary operations cannot be invoked;
- validation tests for malformed or over-broad input;
- read-only tests proving observe tools cannot mutate;
- approval tests for high/critical writes;
- idempotency tests for retryable writes;
- pre-state/rollback tests where writes are supported;
- verification tests independent of mutation response;
- secret-redaction tests for output and audit events.

Production-specific integration tests may live in private deployment repositories, but the public service must keep deterministic unit/contract coverage in `mcp-lib`.
