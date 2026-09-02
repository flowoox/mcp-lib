# Hyper-V MCP

`hyperv-mcp` is a product-neutral, bounded Hyper-V diagnostics service with a strict read-only observe backend and an optional, separately constrained checkpoint-creation write boundary. It follows the shared `mcp-common` security, audit/correlation, approval, idempotency and query-budget contracts.

## Observe tools

The observe surface remains explicitly read-only:

- host summary with VM state counts, migration state and bounded memory-pressure evidence;
- paged VM inventory and one-VM detail;
- virtual-switch inventory;
- per-VM checkpoint and VHD observations;
- replication observations;
- bounded VMMS/Worker event evidence;
- an aggregate-first VM diagnostic bundle that resolves one VM before bounded relationship fan-out.

There is no generic PowerShell, WMI/CIM, WinRM, event-log, guest-command or Hyper-V mutation proxy.

## Pre-change ProductionOnly checkpoints

For controlled update workflows the service can optionally expose exactly one state-changing primitive: **create a VM checkpoint**. The lifecycle is:

```text
hyperv_plan_checkpoint
        |
        +--> resolve configured checkpoint target alias
        +--> bind immutable VM ID
        +--> require VM state Running or Off
        +--> require CheckpointType = ProductionOnly
        +--> enforce existing-checkpoint safety limit
        +--> derive deterministic checkpoint name from target/VM/idempotency/label
        v
out-of-band approval signs exact approvalBinding
        v
hyperv_change_checkpoint
        |
        +--> re-run all preflight checks on the write endpoint
        +--> verify signed approval + exact VM ID/name/intent
        +--> persist pending idempotency receipt
        +--> Checkpoint-VM through a fixed repository-owned script only
        +--> independently read back the exact checkpoint
        +--> persist verified non-secret receipt
        v
hyperv_verify_checkpoint
```

The checkpoint name is deterministic and contains a short digest of the idempotency intent, for example `pre-update--mcp-0123456789ab`. Reusing an idempotency key with a different VM/target/name is rejected. Provider state is never treated as an idempotent success unless a matching verified local receipt exists.

### Why ProductionOnly is mandatory

Automated update checkpoints deliberately require the VM to be preconfigured with `CheckpointType=ProductionOnly`. Hyper-V's `Production` mode may fall back to a standard checkpoint if a production checkpoint cannot be created; this MCP does not accept that fallback for automated production changes. The MCP never calls `Set-VM` to weaken or alter the configured checkpoint type.

Checkpoint creation is high risk and always requires a short-lived signed approval grant. The approval is bound to:

- logical target alias;
- immutable Hyper-V VM ID;
- exact VM name;
- deterministic checkpoint name;
- `ProductionOnly` checkpoint type;
- idempotency key.

The write slice does **not** expose checkpoint restore/apply, delete/merge, rename, VM start/stop/restart, storage changes, switch changes, replication changes or guest commands. Those require separate future workflows rather than broadening this primitive.

## Separate backend authorization boundaries

The existing observe boundary still fails closed unless `HYPERV_BACKEND_READ_ONLY=true`. By default `HYPERV_REQUIRE_JEA=true` requires every observe target alias to use a dedicated WinRM/JEA configuration; unrestricted endpoints such as `Microsoft.PowerShell` are rejected.

Checkpoint creation uses a **different** target map and a **different JEA endpoint**. Enabling it requires all of:

```text
HYPERV_CHECKPOINT_WRITES_ENABLED=true
HYPERV_CHECKPOINT_BACKEND_CONSTRAINED=true
HYPERV_CHECKPOINT_APPROVAL_SECRET=<at least 32 bytes>
HYPERV_CHECKPOINT_RECEIPT_STORE=<persistent JSON state path>
HYPERV_CHECKPOINT_TARGETS_JSON={"hv01":{"computer_name":"hv01.example.invalid","transport":"winrm","configuration_name":"FlowooxHyperVCheckpoint"}}
```

For each logical alias, the checkpoint target must resolve to the same computer as the read-only target but **must not reuse the read-only JEA configuration**. Production checkpoint writes never use local execution.

A checkpoint JEA role capability should expose only the commands required by the fixed scripts, normally `Get-VM`, `Get-VMSnapshot`, and `Checkpoint-VM`, plus the minimal PowerShell language/core commands required by reviewed script code. Do not expose `Set-VM`, `Remove-VMSnapshot`, `Restore-VMSnapshot`, arbitrary `Invoke-Command` input, `Invoke-Expression`, CIM/WMI mutation or unrestricted PowerShell.

Credentials are never MCP tool arguments. WinRM uses the deployment service identity and Kerberos; the constrained JEA endpoint remains the provider-side authorization boundary. The approval signing secret is runtime-only and never returned by MCP tools.

## Clustered VMs

Checkpoint creation remains owned by `hyperv-mcp`; `failovercluster-mcp` does not receive duplicate Hyper-V write privileges. For a clustered VM, first resolve the current role/group `ownerNode` through `failovercluster.group.observe`, then select the deployment-owned Hyper-V target alias for that owner node and run the normal checkpoint plan/change/verify lifecycle.

This separation is intentional: cluster observation determines placement, while the Hyper-V MCP owns the VM checkpoint mutation. If the VM moves between plan and change, the write-side preflight/immutable VM-ID checks fail closed instead of following an arbitrary host supplied by the caller.

## Target configuration

Targets are deployment-owned logical aliases. Public code contains no company hostnames, IPs, credentials or topology.

```text
HYPERV_BACKEND_READ_ONLY=true
HYPERV_REQUIRE_JEA=true
HYPERV_TARGETS_JSON={"hv01":{"computer_name":"hv01.example.invalid","transport":"winrm","configuration_name":"FlowooxHyperVReadOnly"}}
```

A local read-only target is supported only when `HYPERV_REQUIRE_JEA=false`; that is intended for development or a deployment that independently enforces a read-only operating-system boundary. The boolean attestation alone does not make an over-privileged Windows identity read-only.

## Agent load protection

Every observe call receives a monotonic `QueryBudget` covering requests, items, response bytes, fan-out and elapsed time. The shared `ReadOnlyConnector` adds page limits, rate limiting, concurrency caps, response-size enforcement and aggregate-before-fan-out policy. Hyper-V event queries use only fixed VMMS/Worker Admin logs and a bounded lookback window. VHD inspection has an additional operation cap.

Checkpoint creation is intentionally single-VM and single-checkpoint only. It has its own timeout/response limits and a maximum existing-checkpoint count (default `8`) to reduce the risk of unchecked AVHDX/checkpoint-chain growth.

Every successful operation returns a structured secret-free audit/correlation envelope with actor and reason.
