# Docker read-only authorization proxy

`docker-readonly-proxy` is a product-neutral deployment boundary for `docker-mcp`. It is intentionally a separate process from the MCP server and is the only process in the reference deployment that needs access to the Docker Engine Unix socket.

The proxy accepts HTTPS only, requires a bearer token loaded from a runtime file, and forwards only a fixed subset of `GET` requests used by the public Docker MCP adapter. It independently validates the Docker API version, path, query-key set, booleans, page sizes, log/event time windows, event object types and simple container IDs. Any other method, path, version, duplicate query key or unexpected query parameter fails closed. The bearer credential is never forwarded to the Docker daemon.

## Allowed upstream surface

The policy permits only these shapes for the configured API version:

```text
GET /_ping
GET /v1.47/info
GET /v1.47/containers/json?all={true|false}&limit={bounded}
GET /v1.47/containers/{simple-id-or-name}/logs?stdout=true&stderr=true&timestamps=true&tail={bounded}&since={bounded}&until={bounded}
GET /v1.47/containers/{simple-id-or-name}/stats?stream=false&one-shot=true
GET /v1.47/images/json?all=false
GET /v1.47/volumes
GET /v1.47/networks
GET /v1.47/events?since={bounded}&until={bounded}&filters={type-only-json}
```

This is deliberately narrower than Docker's normal API. There is no generic pass-through route and no support for create, exec, attach, start, stop, restart, delete, pull, push, build, inspect or arbitrary query parameters.

## Runtime files

Provision three runtime-only files using the host secret manager or configuration management system:

```text
/run/secrets/docker-readonly-proxy/tls.crt
/run/secrets/docker-readonly-proxy/tls.key
/run/secrets/docker-readonly-proxy/bearer.token
```

Use a certificate issued by the organization's trusted PKI for the exact management DNS name or IP used by `DOCKER_HOST`. Keep `DOCKER_TLS_VERIFY=true` on the MCP side. The proxy does not implement a custom CA bypass; if a private CA is used, install that CA into the MCP runtime trust store instead of disabling TLS verification.

Generate the bearer credential with a cryptographically secure secret generator and keep it out of environment variables, shell history, Git and logs. The proxy reads it from `DOCKER_READONLY_PROXY_BEARER_TOKEN_FILE`; `docker-mcp` receives the same value through its existing runtime-secret mechanism as `DOCKER_AUTH_TOKEN`.

## Example host deployment

1. Install the `flowoox-mcp-docker` package into a dedicated virtual environment under `/opt/flowoox-mcp-docker/.venv`.
2. Create an unprivileged `flowoox-docker-proxy` service account and grant only that account the supplementary group needed to open the local Docker socket. Membership in the Docker socket group is protocol-privileged; do not grant it to the MCP process itself.
3. Copy `readonly-proxy.env.example` to `/etc/flowoox/docker-readonly-proxy.env` and adapt only deployment-specific addresses, file paths and limits.
4. Provision the TLS certificate/key and bearer-token files outside the repository with restrictive permissions.
5. Install `docker-readonly-proxy.service.example` as a site-specific systemd unit and verify its hardening directives on the target distribution with `systemd-analyze security`.
6. Keep the default loopback bind for a same-host MCP deployment. If the MCP runs remotely, bind only a dedicated management address and restrict source IPs with the host/network firewall. Do not expose this listener to user or public networks.
7. Point the MCP service at `https://<management-name>:23760`, set `DOCKER_BACKEND_READ_ONLY=true`, keep `DOCKER_ALLOW_DIRECT_SOCKET=false`, set `DOCKER_TLS_VERIFY=true`, and supply the bearer token through the MCP secret store.

The proxy defaults are intentionally independent from the MCP query budget. Keep proxy limits equal to or tighter than the corresponding MCP limits. A mismatch where the proxy is tighter is safe and produces a denied request; a mismatch where the proxy is broader does not enlarge the MCP tool surface but weakens defense in depth.

## Verification

Before production use, verify at minimum that `/_ping`, `/info` and a bounded container list work through the HTTPS endpoint with the correct bearer token, then confirm that a write method and an unlisted path return denial without reaching Docker. The repository tests exercise the exact allow/deny policy, duplicate/unknown query rejection, log/event windows, page caps, token loading and fail-closed configuration.

The proxy buffers each permitted Docker response only up to `DOCKER_READONLY_PROXY_MAX_RESPONSE_BYTES`, rejects upstream redirects, caps concurrent requests, strips the incoming bearer credential before forwarding, suppresses raw upstream error bodies and emits no request-target access log by default.
