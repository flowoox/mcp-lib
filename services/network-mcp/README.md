# Network MCP

Product-neutral, read-only MCP service for bounded network diagnostics.

The service is intentionally **not** an unrestricted scanner or shell wrapper. Active diagnostics resolve a target once and require every resulting IP address to be contained in the runtime `NETWORK_ALLOWED_CIDRS` boundary before any socket probe occurs.

## Contract

`flowoox.network-diagnostics` v1.1.0 exposes:

- `network.dns.resolve` — bounded resolver evidence after target authorization;
- `network.tcp.reachability` — one explicit TCP port with a bounded timeout;
- `network.route.selection` — kernel source-address selection without invoking a shell;
- `network.path.trace` — separately gated, bounded hop tracing to one authorized numeric destination;
- `network.subnet.validate` — pure IPv4/IPv6 CIDR/address validation;
- `network.diagnostic.bundle` — DNS + route selection + a bounded explicit list of TCP ports.

There is no arbitrary command execution, arbitrary URL fetch, caller-selected executable, packet flood, port range, caller-selected traceroute flags, or unbounded fan-out primitive.

## Target policy

The safe default is loopback only:

```text
NETWORK_ALLOWED_CIDRS=127.0.0.0/8,::1/128
```

A production deployment must explicitly widen that list to the networks the MCP identity is authorized to diagnose, for example:

```text
NETWORK_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8
```

If a hostname returns multiple A/AAAA records, **all** resolved addresses must be allowed. Mixed allowed/denied resolution fails closed rather than probing only a subset. Active TCP/path probes use an already-authorized numeric address, not the original hostname, reducing DNS-rebinding exposure between policy evaluation and probe execution.

Other bounds:

```text
NETWORK_OPERATION_TIMEOUT_SECONDS=5
NETWORK_MAX_RESOLVED_ADDRESSES=16
NETWORK_MAX_PORTS_PER_BUNDLE=8
```

`tcp_reachability` accepts one port from 1–65535. `diagnostic_bundle` accepts only an explicit bounded list; it never expands a port range.

## MCP transport security

The common `MCP_TRUST_BOUNDARY`, Host/Origin allowlist, DNS-rebinding protection, HTTPS requirement for external endpoints, and bearer-token boundary from `mcp-common` apply exactly as for the other services.

## Routing and path semantics

`network.route.selection` asks the local kernel which source IP it would select for an authorized destination by connecting an untransmitted UDP socket.

Hop-by-hop path tracing is separately disabled by default because it creates additional active network traffic:

```text
NETWORK_PATH_TRACE_ENABLED=false
NETWORK_PATH_TRACE_MAX_HOPS=20
NETWORK_PATH_TRACE_PROCESS_TIMEOUT_SECONDS=30
```

When enabled, `network.path.trace` first applies the same DNS/CIDR authorization boundary. It then selects the first already-authorized resolver address and invokes only a fixed absolute operating-system path:

- Unix-like systems: `/usr/bin/traceroute`, `/bin/traceroute`, `/usr/sbin/traceroute`, or `/sbin/traceroute`;
- Windows: `%SystemRoot%\System32\tracert.exe` or `%WINDIR%\System32\tracert.exe`.

The service does not search `PATH`. A discovered candidate must resolve to an executable regular file. No MCP value can select or alter the executable.

The subprocess boundary is intentionally narrow:

- `shell=False` with a fixed absolute `argv[0]`;
- destination is a validated numeric IPv4/IPv6 address, never the hostname;
- reverse DNS is disabled (`-n`/`-d`);
- hop count and per-hop timeout are bounded;
- query count is fixed to one on Unix traceroute;
- no MCP value can become an executable path or arbitrary command-line option;
- child `stdin` and `stderr` are connected to `DEVNULL`;
- the child receives a minimal deterministic environment without `PATH`;
- stdout is written to an anonymous temporary file instead of unbounded in-memory capture;
- output above 32 KiB fails closed;
- only structured hop/address evidence is returned, never raw process output.

At most four numeric addresses are retained per parsed hop. The maximum hop count and process timeout remain independently bounded even if the operating-system utility behaves unexpectedly.

On Linux/Unix the host must provide a compatible `traceroute` binary and any OS capabilities it needs. On Windows the service uses the built-in/supported `tracert` executable when available. If no supported fixed binary exists, the tool fails closed without attempting another command.

## Deployment principle

Network reachability is not authorization. Keep `NETWORK_ALLOWED_CIDRS` narrower than the host's actual routing table and firewall reachability. Organization/customer-specific ranges belong in deployment configuration, not in this public repository.
