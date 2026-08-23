# Infrastructure Security Audit MCP

`flowoox.security-audit` is a product-neutral, bounded **read-only** policy engine for infrastructure security evidence. It deliberately does not become a monolithic administrator MCP: Active Directory, network, FortiGate, Entra and Windows services keep their own least-privilege backend boundaries, while an orchestrator such as n8n or an agent maps selected bounded observations into the typed `EvidenceFact` schema consumed here.

## Architecture and safety boundary

The service has no direct infrastructure backend URL, token, PowerShell, Graph, FortiOS, LDAP or shell execution surface. It cannot issue arbitrary queries or accept arbitrary policy definitions. The v1 control catalog is repository-owned and fixed, tool registration is explicit, and the only audit operation is read-only.

A caller may submit at most 200 evidence facts per invocation. Facts contain only a fixed evidence kind, matching source family, subject identifier, source operation, timezone-aware observation time and one bounded boolean or non-negative integer value. Raw event logs, directory objects, firewall configuration, credentials, command output and other backend payloads do not belong in this contract.

For repeated evidence of the same kind and subject, the newest observation wins and older observations are counted as stale. Conflicting values with the same timestamp fail closed instead of selecting one nondeterministically. Findings are sorted deterministically and returned with severity, expected state and a remediation hint.

## Orchestration model

A reference flow is:

`specialized read-only MCP -> bounded normalized fact mapping -> security-audit-mcp -> finding -> specialized plan/approval/change/verify MCP`

The audit service never executes remediation. A finding such as an unhealthy FortiGate HA state or AD replication failure is evidence for an administrator or orchestration workflow. Any later change must go back through the owning specialized MCP and its separate least-privilege write identity, target-bound approval, idempotency, pre-state, rollback intent and independent verification controls.

This separation also keeps the public repository product-neutral: environment-specific topology, tenant IDs, OUs, hostnames, policy names, credentials and organization policy mappings remain in deployment configuration or orchestration, not in this service.

## V1 evidence and controls

The current catalog covers bounded signals for AD replication and secure-channel health, allowlisted network diagnostic failures, FortiGate HA and permissive-policy counts, Entra Conditional Access presence, and Windows pending-reboot, critical-event and required-service health. The catalog is intentionally conservative; additional controls should be added only after the source MCP exposes a stable, minimal typed observation that can be evaluated without importing privileged raw data.

## Endpoint and audit metadata

Every evaluation returns the shared `mcp-common` `OperationResult` and `AuditEvent` envelopes with actor, reason and correlation ID. Audit metadata contains counts, not submitted evidence payloads. The service also applies the shared per-call item, response-byte and total-time query budget to prevent agent workflows from turning a security scan into an unbounded workload.

The MCP HTTP endpoint reuses the common transport trust-boundary controls. Keep it on loopback or an authenticated internal management plane unless an explicit external trust configuration is required.

## Production deployment

Copy `.env.example` into the deployment configuration layer and keep environment values outside Git. The container image runs as a non-root user; the compose example is read-only, drops Linux capabilities and enables `no-new-privileges`. Because this service does not connect directly to infrastructure backends, no backend credential is configured here.

An orchestrator should validate source MCP success first, map only the minimum facts required by the fixed catalog, preserve the source observation timestamp and operation ID, and propagate one correlation ID across the whole diagnostic workflow.

## Development and verification

Repository CI installs the locked dependency graph, runs Ruff, Pytest and `compileall`, and builds the non-root production container. Tests cover strict evidence typing, source/kind binding, bounded batches, deterministic rule evaluation, stale evidence handling, fail-closed timestamp conflicts and the explicit read-only capability contract.
