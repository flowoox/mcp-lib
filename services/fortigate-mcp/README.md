# FortiGate Observe MCP

Product-neutral, **read-only** MCP service for bounded FortiOS observation.

The service is not a generic HTTP proxy and not a configuration bypass. It exposes six static `GET` resources:

- system status;
- HA configuration;
- interface inventory;
- static routes;
- IPv4 firewall-policy inventory;
- IPsec phase-1 inventory.

No MCP argument can choose the FortiGate URL, VDOM, HTTP method, API path, headers, TLS behavior, executable or arbitrary query parameters.

## Runtime configuration

```text
FORTIGATE_BASE_URL=https://fortigate.example.net
FORTIGATE_API_TOKEN=<FortiOS REST API token>
FORTIGATE_VDOM=root
FORTIGATE_CA_BUNDLE=/run/secrets/fortigate-ca.pem   # optional
FORTIGATE_TIMEOUT_SECONDS=10
FORTIGATE_MAX_RESPONSE_BYTES=2097152
FORTIGATE_MAX_ITEMS=500
```

`FORTIGATE_BASE_URL` must be one HTTPS origin with no userinfo, path, query or fragment. TLS verification is always enabled. A private CA can be supplied through an absolute regular-file path; there is no `verify=false` mode.

The token is sent only as:

```text
Authorization: Bearer <token>
```

It is never put into a URL, MCP output or upstream error message. HTTP redirects are blocked, environment proxy variables are ignored, response bodies are bounded, and upstream error bodies are never relayed.

## Least privilege

Create a dedicated FortiOS REST API administrator with:

- read-only permissions limited to the required system, network, policy and VPN resources;
- trusted hosts restricted to the MCP runtime source addresses;
- access only to the intended VDOMs;
- optional client-certificate/PKI matching where appropriate.

Do not use a `super_admin` token for this observe-only service.

## Output boundary

The service does not return raw FortiOS responses. Each endpoint is projected onto a selected field set. Unknown fields are omitted, common secret-bearing keys are redacted recursively, FortiOS `ENC ...` values are redacted, nested strings/lists/maps are bounded, and collection results are capped.

The initial contract is `flowoox.fortigate-observe` v1.0.0. Configuration writes, policy changes, object creation and operational actions are intentionally absent. A future write contract must use plan/change/verify, signed approval, immutable target binding, pre-state capture and rollback/verification.
