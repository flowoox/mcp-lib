# Windows Server Diagnostics MCP

`flowoox.windows-diagnostics` is a product-neutral, bounded **read-only** MCP service for Windows Server diagnostics. It is intended for administrators and AI agents that need structured evidence without receiving a generic PowerShell, WinRM, WMI/CIM, registry, event-log, or filesystem execution primitive.

## Safety model

The service starts fail-closed. `WINDOWS_BACKEND_READ_ONLY=true` is required before a backend transport can be created. Treat this flag as an operator attestation that the service identity is least-privilege and read-only. For remote WinRM targets, `WINDOWS_REQUIRE_JEA=true` is the default and rejects the standard unrestricted PowerShell endpoints; use a dedicated constrained JEA endpoint that exposes only the read commands needed by the repository-owned probes.

All target hostnames and JEA endpoint names are deployment configuration. Agent/model callers choose only a logical target ID. PowerShell source is repository-owned and statically selected from an allowlist; caller data is serialized separately and is never interpolated into PowerShell source or argv. Child processes run with `shell=False`, fixed executable basenames, bounded input, timeout, output files and response-byte limits.

The observe slice exposes no mutation tool. It does not return service binary paths, process command lines, process owners, executable paths, environment variables, certificate private keys, registry values, arbitrary event logs, raw PowerShell output, or credentials. If a future write layer is added, it must use a separate least-privilege identity plus `plan -> approval -> change -> verify`, idempotency, pre-state, rollback intent and independent read-back verification.

## Read-only tools

The v1 contract includes host/OS health and reboot-pending state, service inventory, process inventory with only name/PID/CPU/working-set metrics, Windows feature inventory, bounded event-log observations, certificate metadata from three fixed LocalMachine stores, installed hotfix inventory, a minimal Hyper-V host summary, and a shared-budget diagnostic bundle.

Every agent-facing operation carries actor/reason/correlation metadata and one `mcp-common` query budget. The shared connector enforces request, item, byte, fan-out and total-time limits together with pagination, deterministic sampling, concurrency caps, rate limiting and aggregate-before-fan-out policy.

## Configuration

Copy `.env.example` into the deployment secret/configuration layer. Do not commit environment-specific values.

`WINDOWS_TARGETS_JSON` maps logical IDs to deployment targets. A local target must use `computer_name="."`. Remote targets require a configured endpoint name. Example:

```json
{
  "local": {"computer_name": ".", "transport": "local"},
  "member-a": {
    "computer_name": "server01.example.test",
    "transport": "winrm",
    "configuration_name": "McpReadOnly"
  }
}
```

`WINDOWS_ALLOWED_EVENT_LOGS` is an explicit comma-separated allowlist. The default is `System,Application`; callers cannot name a log outside it. Event queries are time-bounded and message text is opt-in, flattened and capped to 512 characters.

## Production deployment

Run the service on a Windows management host with Python 3.12+ and Windows PowerShell or PowerShell 7. The default local target is useful for a dedicated management host. For remote management, use Kerberos and a constrained JEA endpoint; keep the service identity outside local/domain administrator groups and grant only the observation rights required by the selected probes. Firewall and WinRM authorization remain deployment responsibilities.

The MCP HTTP endpoint reuses `mcp-common` trust-boundary controls. Keep it on loopback or an authenticated internal management plane unless an explicit external trust configuration is required.

## Development and verification

Portable unit/contract tests run on Linux CI without executing PowerShell. A dedicated `windows-latest` smoke job executes the fixed host probe through real Windows PowerShell and validates the typed projection. Repository CI also runs the full Python package lint/test/compile gates.
