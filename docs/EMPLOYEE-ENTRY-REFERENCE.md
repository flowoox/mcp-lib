# Employee-entry reference orchestration

This repository intentionally does **not** provide a monolithic employee-onboarding MCP. The reference workflow in `docs/infrastructure/employee-entry-reference-v1.json` is a product-neutral orchestration contract for n8n or agent runtimes. Each specialized MCP keeps its own backend identity, allowlist, query budget and write controls.

## Security boundary

The orchestrator carries references, not deployment values. Public workflow bindings may point only to `input.*`, `steps.*` or `control.*`; literal hostnames, OUs, tenant identifiers, credentials, approval tokens, passwords, IPs and company policy values are rejected by the shared `mcp_common.orchestration` contract.

State changes remain `plan -> approval -> change -> verify`. The reference currently performs one concrete write lifecycle: creation of a **disabled** AD user through `ad-mcp`. The change step requires the same idempotency reference used by its plan plus an out-of-band approval grant. The independent verify step must depend on the change. No orchestrator bypass exists for AD write enablement or approval validation.

Entra, network, n8n and security-audit calls are read-only. They are used as bounded pre/post-flight evidence only. The workflow does not add generic Graph, PowerShell, n8n API, HTTP or shell proxying.

## Reference flow

1. Observe the deployed n8n automation surface with `n8n.workflows.list`.
2. Observe the Entra tenant boundary with `entra.tenant.observe`.
3. Resolve the deployment-supplied directory DNS name through the bounded `network.dns.resolve` tool.
4. Observe AD domain health with `ad.domain.summary`.
5. Plan creation of a disabled AD user with collision/OU preflight and a caller-supplied idempotency key.
6. Obtain the exact out-of-band approval grant in the orchestrator's control plane. The workflow itself never mints approvals.
7. Execute `ad.user.provision-disabled.change` through the separately enabled AD write boundary.
8. Independently verify the user through `ad.user.provision-disabled.verify`.
9. Normalize bounded evidence in the orchestrator and evaluate it through `security.audit.evaluate`.

The reference deliberately stops with the account disabled. Password bootstrap, group membership, account enablement, M365 licensing, endpoint enrollment and application-specific provisioning should be added only as explicit specialized MCP lifecycle blocks. Company-specific OU/group mappings and policy decisions belong in deployment configuration, not in this public repository.

## n8n / agent implementation rules

Use one correlation ID for the complete run and propagate it to every MCP call. Store only secret references or signed approval artifacts in the orchestration control plane; never copy resolved passwords or backend API credentials into workflow JSON, execution logs or agent prompts. Keep MCP credentials separated per service and use read-only identities for observe services.

Before a change node runs, verify that its plan succeeded, its exact approval artifact is present and unexpired, and its idempotency key is unchanged. After a change, always run the declared verify node. A failed verify should stop the workflow and route the captured pre-state plus audit metadata to human remediation; the orchestrator must not improvise rollback commands.

Fan-out should remain bounded. Employee-specific operations should target one identity at a time. Inventory/evidence steps should use the limits enforced by the underlying MCPs instead of fetching whole tenants, forests or workflow histories into the agent context.

## Deployment-owned inputs

The v1 reference expects actor/reason metadata, a directory DNS name, the minimum disabled-user identity fields, an OU DN and an idempotency key. Those values are runtime inputs. `control.correlation_id`, `control.approvals.*` and `control.normalized_security_evidence` are produced by the deployment/orchestration control plane and are intentionally not repository configuration.

## Extension policy

Add a new employee-entry step only when the target specialized MCP exposes a typed allowlisted capability with the required lifecycle and least-privilege backend boundary. For any state-changing capability, add plan/change/verify as one lifecycle group, require explicit approval for risky writes, preserve one idempotency reference across plan/change, and keep company-specific topology/policy outside the workflow definition.
