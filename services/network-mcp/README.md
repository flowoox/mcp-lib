# Network MCP

Product-neutral, read-only MCP service for bounded network diagnostics.

The service is intentionally **not** an unrestricted scanner or shell wrapper. Active diagnostics resolve a target once and require every resulting IP address to be contained in the runtime `NETWORK_ALLOWED_CIDRS` boundary before any socket probe occurs.

## Initial contract

`flowoox.network-diagnostics` v1.0.0 exposes:

- `network.dns.resolve` — bounded resolver evidence after target authorization;
- `network.tcp.reachability` — one explicit TCP port with a bounded timeout;
- `network.route.selection` — kernel source-address selection without invoking traceroute or a shell;
- `network.subnet.validate` — pure IPv4/IPv6 CIDR/address validation;
- `network.diagnostic.bundle` — DNS + route selection + a bounded explicit list of TCP ports.

There is no arbitrary command execution, arbitrary URL fetch, caller-selected executable, packet flood, port range, or unbounded fan-out primitive.

## Target policy

The safe default is loopback only:

```text
NETWORK_ALLOWED_CIDRS=127.0.0.0/8,::1/128
```

A production deployment must explicitly widen that list to the networks the MCP identity is authorized to diagnose, for example:

```text
NETWORK_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8
```

If a hostname returns multiple A/AAAA records, **all** resolved addresses must be allowed. Mixed allowed/denied resolution fails closed rather than probing only a subset. The active socket connection uses the already-authorized numeric address, not the original hostname, reducing DNS-rebinding exposure between policy evaluation and connect.

Other bounds:

```text
NETWORK_OPERATION_TIMEOUT_SECONDS=5
NETWORK_MAX_RESOLVED_ADDRESSES=16
NETWORK_MAX_PORTS_PER_BUNDLE=8
```

`tcp_reachability` accepts one port from 1–65535. `diagnostic_bundle` accepts only an explicit bounded list; it never expands a port range.

## MCP transport security

The common `MCP_TRUST_BOUNDARY`, Host/Origin allowlist, DNS-rebinding protection, HTTPS requirement for external endpoints, and bearer-token boundary from `mcp-common` apply exactly as for the other services.

## Routing semantics

`network.route.selection` asks the local kernel which source IP it would select for an authorized destination by connecting an untransmitted UDP socket. It does not currently claim to be a hop-by-hop traceroute. A future path-trace capability must remain an explicit, bounded primitive with the same target policy and without generic shell execution.

## Deployment principle

Network reachability is not authorization. Keep `NETWORK_ALLOWED_CIDRS` narrower than the host's actual routing table and firewall reachability. Organization/customer-specific ranges belong in deployment configuration, not in this public repository.
