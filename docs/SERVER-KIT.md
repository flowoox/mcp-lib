# Reusable MCP server kit

The goal of the common kit is to make a new MCP service mostly a matter of declaring a contract and implementing upstream-specific handlers.

## Desired developer experience

A new service should be able to start from:

```text
service.yaml
src/handlers/
tests/
```

Conceptual manifest:

```yaml
id: example-service
contract: flowoox.example.v1
transport: streamable-http
capabilities:
  - id: resource.list
    risk: read
  - id: resource.restart
    risk: controlled-write
```

The kit should provide the repetitive platform concerns:

1. application/server bootstrap
2. `get_capabilities`
3. schema validation
4. normalized errors
5. correlation/request IDs
6. logging and audit hooks
7. timeout handling
8. optional idempotency-key handling
9. auth adapter interface
10. policy/approval hook interface
11. health/readiness endpoints
12. contract-test harness

## Handler boundary

Handlers implement only upstream-specific behavior. They should receive already validated input plus an execution context containing actor/correlation information and should return typed results.

They must not:

- parse arbitrary model-generated command strings
- read secrets from tool arguments
- create an undocumented generic HTTP proxy
- expose arbitrary shell, SQL or provider commands
- bypass an authoritative upstream permission model

## Contract versioning

Capability contracts are versioned independently of service/container versions. Additive changes can remain within a major version; incompatible semantic changes require a new contract major.

## Public/private reuse

The kit stays public and product-neutral. A private Tekoda integration repository can depend on it to expose internal APIs through MCP without moving internal business logic, topology or credentials into this public repository.
