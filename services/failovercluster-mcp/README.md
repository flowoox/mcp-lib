# Failover Cluster MCP

Product-neutral, bounded and read-only diagnostics for Windows Server Failover Clustering.

The service is designed for administrators, n8n workflows and AI agents that need useful cluster evidence without receiving a generic PowerShell, WMI/CIM or cluster-management proxy.

## Safety model

Production defaults are deliberately fail-closed:

- `FAILOVERCLUSTER_BACKEND_READ_ONLY=true` is mandatory.
- `FAILOVERCLUSTER_REQUIRE_JEA=true` is the default.
- targets are deployment-owned logical aliases; callers cannot supply arbitrary hosts.
- unrestricted PowerShell remoting configurations such as `Microsoft.PowerShell` are rejected while JEA is required.
- only repository-owned static probes are executable.
- every exposed tool is `observe` / `read_only`; there is no group move, failover, resource restart, node pause/resume, quorum mutation, CSV mutation or network mutation.
- no arbitrary script, WMI/CIM query, event-log name or shell argument is exposed.
- pagination, response bytes, timeout, item count, concurrency, rate and total query budget are bounded through `mcp-common`.
- diagnostic bundles aggregate cluster state before relationship fan-out.
- responses use the shared audit/correlation envelope and do not return credentials.

`FAILOVERCLUSTER_BACKEND_READ_ONLY=true` is an explicit deployment attestation, not a substitute for OS-level least privilege. The service identity and JEA endpoint must also be constrained so that the backend cannot mutate cluster state.

## Observe tools

The public contract is `flowoox.failovercluster-diagnostics` v1.0.0 and exposes:

- `failovercluster.cluster.observe` — aggregate cluster availability, node/group/resource state counts, CSV count and quorum summary.
- `failovercluster.node.list` — bounded node inventory and vote/drain state.
- `failovercluster.group.list` — bounded roles/groups and ownership/state.
- `failovercluster.group.observe` — exact-name group detail with a bounded resource relationship set.
- `failovercluster.resource.list` — bounded resources, optionally filtered by one exact group name.
- `failovercluster.network.list` — bounded cluster network state/role/metric evidence.
- `failovercluster.storage.list` — bounded CSV ownership and capacity/free-space evidence.
- `failovercluster.quorum.observe` — quorum mode and witness resource/type.
- `failovercluster.event.list` — bounded events from the fixed `Microsoft-Windows-FailoverClustering/Operational` log only.
- `failovercluster.cluster.diagnose` — aggregate-first bundle of cluster, nodes, groups, CSVs, quorum and recent error evidence.

All tools require `actor` and `reason`; a caller may also supply a UUID `correlation_id` so evidence can be joined across MCP services.

## JEA deployment

Use a dedicated endpoint such as `Flowoox.FailoverCluster.ReadOnly`. Do not bind the MCP service to an endpoint that also permits administrative cluster commands.

The endpoint should expose only the read-side commands needed by the static probes, normally including:

- `Get-Cluster`
- `Get-ClusterNode`
- `Get-ClusterGroup`
- `Get-ClusterResource`
- `Get-ClusterNetwork`
- `Get-ClusterSharedVolume`
- `Get-ClusterQuorum`
- `Get-WinEvent`
- the minimal PowerShell language/core pipeline commands required by the signed/deployment-reviewed probe code

Do **not** expose state-changing FailoverClusters cmdlets such as `Move-ClusterGroup`, `Start-ClusterGroup`, `Stop-ClusterGroup`, `Suspend-ClusterNode`, `Resume-ClusterNode`, `Add-Cluster*`, `Remove-Cluster*`, `Set-Cluster*`, `Start-ClusterResource`, `Stop-ClusterResource` or arbitrary `Invoke-Expression`/script execution.

Prefer a dedicated service account or gMSA whose Windows permissions are independently limited to cluster observation. Where operational policy permits, place a local authorization proxy/JEA endpoint on the management tier rather than granting the MCP process broad administrator rights.

## Target configuration

Targets are external deployment configuration and intentionally absent from the repository:

```text
FAILOVERCLUSTER_TARGETS_JSON={"prod":{"computer_name":"cluster-access.example.invalid","transport":"winrm","configuration_name":"Flowoox.FailoverCluster.ReadOnly"}}
```

Callers use only the alias (`prod`). They cannot override hostname, transport or JEA configuration.

Local execution exists for development/integration testing but requires the operator to explicitly set `FAILOVERCLUSTER_REQUIRE_JEA=false`; it is not the production default.

## Agent/load protection

The service reuses `mcp-common` `ReadOnlyConnector` and `QueryBudget` controls. Broad work is rejected before dispatch where possible, and oversized backend responses are rejected before JSON parsing. Default budgets cap request count, items, fan-out, response bytes, elapsed time, concurrency and request rate.

For agent workflows, call `cluster.observe` first. Only expand to exact roles/resources when the aggregate state indicates a problem. `cluster.diagnose` follows the same aggregate-first approach and deliberately omits message bodies from its recent-error sample.

## Writes

Observe v1 contains no write layer. If a future concrete operational workflow requires failover, role movement, maintenance/drain or resource restart, implement it as a separate opt-in identity and contract using the repository's `plan -> approval -> change -> verify` lifecycle, exact-target approvals, idempotency keys, pre-state capture, rollback declaration where feasible and independent read-back verification. Do not add generic PowerShell or generic cluster mutation to this service.
