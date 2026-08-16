# Reusable event and typed-action MCP patterns

This document defines the reusable public patterns extracted from the Tekoda/PocketOps architecture. Tekoda-specific tenant topology, private endpoints, customer logic and privileged assumptions remain outside `mcp-lib`.

## Pattern: event consumer façade

MCP tools may expose normalized event reads to an agent, for example:

```text
events.list
incident.inspect
incident.acknowledge
```

The MCP server must call an authoritative upstream API. It must not become the event store, authorization authority or tenant mapper.

## Pattern: typed action façade

Mutating tools expose fixed capability IDs and typed parameters rather than arbitrary shell/HTTP requests.

Good:

```text
security.ip.temporary_block(ip, duration, scope)
operation.retry(operation_id)
service.instance.create(definition_id, parameters, idempotency_key)
```

Forbidden as a generic privileged pattern:

```text
http.request(method, url, headers, body)
shell.exec(command)
kubernetes.apply(raw_yaml)
terraform.apply(raw_hcl)
```

## Required properties

- upstream authorization remains authoritative
- tenant/project scope is preserved end to end
- mutations are disabled by default where a deployment has not explicitly enabled them
- idempotency is required for create/retry-safe mutations
- approval requirements cannot be bypassed by MCP
- secrets are runtime references, never tool arguments exposed to the model unless the upstream contract explicitly requires a redacted identifier
- every mutation is auditable
- event payloads may reference action capability IDs but never executable code

## Pattern: message/notification sender

A reusable sender façade may accept a destination identifier, title/body, priority and typed action references. It must not accept arbitrary provider credentials from an agent.

```text
message.send(recipient_ref, title, body, priority, action_refs[])
```

Provider-specific delivery adapters remain separate from the generic contract.

## Promotion rule

Only generally reusable contracts and helpers belong here. Tekoda-specific implementations belong in `flowoox/tekoda-integrations`; canonical Tekoda schemas and capability IDs belong in `flowoox/tekoda-dev`.
