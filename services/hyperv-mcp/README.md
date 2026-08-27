# Hyper-V MCP

`hyperv-mcp` is a product-neutral, bounded **read-only** diagnostics service for Microsoft Hyper-V hosts. It follows the shared `mcp-common` security, audit/correlation and query-budget contracts.

## Observe v1

The tool surface is intentionally explicit:

- host summary with VM state counts, migration state and bounded memory-pressure evidence;
- paged VM inventory and one-VM detail;
- virtual-switch inventory;
- per-VM checkpoint and VHD observations;
- replication observations;
- bounded VMMS/Worker event evidence;
- an aggregate-first VM diagnostic bundle that resolves one VM before bounded relationship fan-out.

There is no generic PowerShell, WMI/CIM, WinRM, event-log, guest-command or Hyper-V mutation tool. Observe v1 cannot start/stop/restart VMs, create/remove checkpoints, attach storage, alter switches, change replication, invoke guest commands or modify cluster state.

## Read-only backend boundary

Startup fails unless `HYPERV_BACKEND_READ_ONLY=true` is explicitly set. By default `HYPERV_REQUIRE_JEA=true` also requires every configured target alias to use a dedicated WinRM/JEA session configuration. Unrestricted endpoints such as `Microsoft.PowerShell` are rejected.

This is deliberate: the MCP read-only contract is only useful when the backend authorization boundary is also constrained. JEA role capabilities should expose only the cmdlets needed by the fixed probes, for example `Get-VMHost`, `Get-VM`, `Get-VMNetworkAdapter`, `Get-VMIntegrationService`, `Get-VMSnapshot`, `Get-VMSwitch`, `Get-VMHardDiskDrive`, `Get-VHD`, `Get-VMReplication`, `Get-WinEvent`, plus the minimal utility cmdlets needed by the repository-owned scripts. Do not grant a service identity local/domain administrator rights merely to satisfy the adapter.

A local target is supported only when `HYPERV_REQUIRE_JEA=false`; that is intended for a deployment that can independently enforce a read-only operating-system identity/proxy boundary. The boolean attestation alone does not make an over-privileged Windows account read-only.

## Target configuration

Targets are deployment-owned logical aliases. Public code contains no company hostnames, IPs, credentials or topology.

```text
HYPERV_BACKEND_READ_ONLY=true
HYPERV_REQUIRE_JEA=true
HYPERV_TARGETS_JSON={"hv01":{"computer_name":"hv01.example.invalid","transport":"winrm","configuration_name":"FlowooxHyperVReadOnly"}}
```

Credentials are never MCP tool arguments. WinRM uses the service identity and Kerberos. External MCP exposure additionally uses the shared `MCP_TRUST_BOUNDARY=external`, HTTPS public URL and bearer-token controls.

## Agent load protection

Every tool call receives a monotonic `QueryBudget` covering requests, items, response bytes, fan-out and elapsed time. The shared `ReadOnlyConnector` adds page limits, rate limiting, concurrency caps, response-size enforcement and aggregate-before-fan-out policy. Hyper-V event queries use only the fixed VMMS/Worker Admin logs and a bounded lookback window. VHD inspection has an additional per-operation page cap.

Every successful observation returns a structured read-only `AuditEvent`, including actor, reason and correlation ID without credentials.
