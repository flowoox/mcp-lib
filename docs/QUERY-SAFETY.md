# Query budgets and read-only connector boundary

Agent diagnostics can overload a healthy backend even when every individual request is read-only.
`mcp-common` therefore separates the agent-facing tool contract from a narrow provider adapter and
enforces a second load boundary before the adapter is called.

## Shared building blocks

`mcp_common.query_budget.QueryBudget` is created per MCP tool invocation. One instance must be
shared by every page and downstream call caused by that invocation. It accounts for:

- backend request count;
- returned item count before output sampling;
- raw response bytes reported by the adapter;
- downstream fan-out; and
- one monotonic total deadline, including queueing and rate-limit waits.

Reservations fail before backend work starts. Responses that exceed an item or byte budget fail
closed before their content is returned. The provider adapter must additionally cap bytes while
streaming; the common post-response check is defense in depth, not permission to buffer an
unbounded body.

`mcp_common.read_only_connector.ReadOnlyConnector` accepts operations, not URLs or HTTP methods.
Its static policy provides the only operation allowlist and enforces:

- an explicitly declared read-only backend transport by default;
- bounded page and sample sizes;
- per-request and total timeouts;
- a concurrency semaphore and start-rate limit;
- aggregation before multi-target fan-out;
- raw response byte limits; and
- product-neutral cache hints.

Sampling is deterministic (`head` or evenly distributed) and happens after budget accounting, so
sampling cannot hide expensive upstream work. Cache hints are advisory to the caller; they never
weaken authorization or make credentials part of a cache key returned to an agent.

## Adapter requirements

A service-specific adapter must:

1. map each allowlisted operation to a fixed upstream method and path;
2. validate service-specific typed parameters and opaque pagination cursors;
3. keep base URLs, credentials, certificate paths and topology in runtime configuration;
4. use a least-privilege, read-only upstream identity or a read-only proxy/API role where the
   backend supports one;
5. stream and reject oversized responses before parsing them;
6. normalize outputs and remove secrets, environment variables and unnecessary raw payloads; and
7. emit audit/correlation metadata without copying backend result data into the audit event.

If an upstream cannot create a genuinely read-only identity (for example, an unrestricted Docker
Engine socket), production should put an authorization proxy in front of it. Merely mounting a Unix
socket read-only does not make its protocol read-only. A direct privileged endpoint therefore needs
a separate explicit operator override and remains discouraged.

## Write separation

The read-only connector cannot be upgraded into a write connector by adding an operation name.
Mutations use a distinct adapter and identity, remain disabled by default, and embed the shared
`ChangePlan`, approval, idempotency, pre-state, rollback and independent verification contracts.
This keeps observe-only deployments possible for every infrastructure MCP.

## Typical per-tool flow

```text
typed MCP input
  -> explicit tool allowlist
  -> per-call QueryBudget
  -> ReadOnlyConnector policy
  -> service adapter fixed operation/path
  -> read-only backend identity
  -> bounded normalized page + cache hint
  -> operation/audit envelope with correlation ID
```
