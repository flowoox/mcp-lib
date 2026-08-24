# Docker MCP

Product-neutral, read-only and fail-closed Docker Engine diagnostics using
`flowoox.docker-diagnostics` v1.1.

The current observe slice exposes:

- daemon reachability plus normalized system/resource health;
- bounded running or stopped container inventory;
- sampled container-to-image, network, volume and published-port relationships;
- finite historical container log tails with line, byte and time-window bounds;
- finite recent Docker event windows with explicit object-type filters and minimized actor attributes; and
- one aggregate diagnostic bundle sharing a single query budget.

It does not expose create, start, stop, restart, kill, delete, pull, push, build, exec, attach,
arbitrary API paths, arbitrary HTTP methods or raw inspect payloads. Container commands, labels,
environment variables and host-side mount source paths are deliberately not returned. Log access is
historical-only: the adapter never sets `follow=true`, always supplies a finite `since`/`until`
window, caps returned lines and response bytes, and applies best-effort credential-pattern redaction.
Remaining log content must still be treated as potentially sensitive.

## Backend boundary

Production should point `DOCKER_HOST` at an HTTPS authorization proxy whose credential can call only
the GET endpoints required by this service:

```text
GET /_ping
GET /v1.47/info
GET /v1.47/containers/json
GET /v1.47/containers/{approved-container}/logs
GET /v1.47/events
```

The proxy should independently restrict container identifiers and query parameters where possible;
the MCP adapter also validates simple Docker IDs/names and emits only fixed query keys. Required
runtime configuration:

```text
DOCKER_HOST=https://docker-readonly.example.invalid
DOCKER_BACKEND_READ_ONLY=true
DOCKER_AUTH_TOKEN=<runtime secret, when the proxy requires one>
DOCKER_TLS_VERIFY=true
```

The base URL and token are never returned by `get_capabilities` or audit output. The adapter rejects
redirects and buffers no body beyond `DOCKER_MAX_RESPONSE_BYTES`.

A Docker Unix socket is protocol-privileged even if its filesystem mount uses `:ro`; callers can
still send mutating Engine API requests through such a socket. Direct sockets are therefore denied
unless both of these explicit settings are present:

```text
DOCKER_HOST=unix:///var/run/docker.sock
DOCKER_BACKEND_READ_ONLY=true
DOCKER_ALLOW_DIRECT_SOCKET=true
```

That override only attests the deployment decision. The MCP adapter still issues fixed GET requests,
but a read-only proxy or Docker authorization plugin is the recommended production control.

## Agent load protection

Defaults are intentionally small and configurable by the operator:

```text
DOCKER_MAX_PAGE_SIZE=100
DOCKER_MAX_SAMPLE_SIZE=50
DOCKER_REQUEST_TIMEOUT_SECONDS=5
DOCKER_MAX_RESPONSE_BYTES=1048576
DOCKER_MAX_CONCURRENCY=2
DOCKER_RATE_LIMIT_PER_SECOND=4
DOCKER_MAX_LOG_WINDOW_SECONDS=3600
DOCKER_MAX_LOG_LINE_CHARS=2000
DOCKER_MAX_EVENT_WINDOW_SECONDS=300

DOCKER_BUDGET_MAX_REQUESTS=4
DOCKER_BUDGET_MAX_ITEMS=200
DOCKER_BUDGET_MAX_RESPONSE_BYTES=2097152
DOCKER_BUDGET_MAX_FAN_OUT=4
DOCKER_BUDGET_TIMEOUT_SECONDS=15
```

Container logs use Docker's upstream `tail`, `since` and `until` parameters, with both stdout and
stderr requested and timestamps enabled. Multiplexed Docker streams are normalized without exposing
raw framing. Event queries always include both `since` and `until`, default to the `container` event
type, and accept only the fixed `container`, `image`, `volume`, `network` or `daemon` type set. Actor
attributes are reduced to a small safe allowlist (`name`, `image`, `container`, `exitCode`, `signal`);
labels are not returned.

Sampling is applied only after raw returned items count against the budget. The current Engine list
endpoint does not provide a stable opaque cursor, so the service refuses caller cursors rather than
pretending pagination is stable. A page that exactly reaches its limit is conservatively marked
`truncated`.

Every diagnostic requires `actor` and `reason`; callers may propagate a UUID `correlation_id`.
Audit events carry those fields without duplicating Docker result data.

## Future write layer

Writes are not part of this contract. A future optional write layer requires a separate backend
identity and explicit operation allowlist. Every mutation must use plan/change/verify, approval,
idempotency, pre-state capture, rollback metadata where possible and independent post-change health
verification. Observe-only deployments remain supported.
