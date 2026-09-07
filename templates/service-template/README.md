# MCP service template

Copy this directory when starting a new public MCP service.

## Rename

Replace:

- package name `example_mcp`
- project name `flowoox-mcp-example`
- console script `mcp-example`
- service title and contract ID in `contract.py`
- internal service hostname `mcp-example` passed to `build_mcp_server_security`

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
mcp-example
```

## HTTP trust boundary

The template deliberately uses the repository's shared `flowoox-mcp-common` HTTP security boundary. The default is `MCP_TRUST_BOUNDARY=internal` on loopback and still enables DNS-rebinding Host/Origin validation.

Do not remove `build_mcp_server_security`, `transport_security`, `auth`, or `token_verifier` when copying the template. If a service is intentionally exposed through an HTTP reverse proxy, set `MCP_TRUST_BOUNDARY=external`, configure the canonical HTTPS `MCP_PUBLIC_URL`, and provision `MCP_AUTH_TOKEN` through the deployment secret store. External mode fails closed without those values. Optional `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS` entries must describe explicit trusted request authorities; do not add broad wildcards merely to satisfy a proxy.

Reverse-proxy `X-Forwarded-*` headers are not an authorization source. Keep the externally visible hostname/origin represented by `MCP_PUBLIC_URL` and the explicit allowlists, and configure the proxy to replace rather than blindly trust client-supplied forwarding headers. Never put bearer credentials in URLs, repository files, logs, or origin/host configuration.

The template intentionally contains only one read-only example tool. Add new tools explicitly and keep upstream-specific behavior in handlers/clients instead of building generic shell, SQL or arbitrary HTTP proxy tools. Outbound HTTP clients must separately validate their own destination/redirect/SSRF trust boundaries; inbound MCP Host/Origin protection does not make arbitrary egress safe.

For Tekoda-private integrations, copy the same pattern into the private integration repository and call authoritative SSIO/Odoo/internal APIs through their normal authorization and audit paths.
