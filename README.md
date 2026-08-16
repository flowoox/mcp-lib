# mcp-lib

Public, reusable MCP services and MCP building blocks maintained under `flowoox`.

The repository started with music-oriented services, but its role is broader: provide a small product-neutral MCP toolkit plus selected public connectors that are useful outside the Tekoda platform.

**Product/business logic and private Tekoda topology do not belong here.** Private platform adapters live in `flowoox/tekoda-integrations` and may reuse patterns/helpers from this repository.

## Architecture

```text
Public MCP services
      |
      +-- Soulseek MCP
      +-- Traxx MCP
      +-- future reusable connectors
      |
      +-- templates/service-template
      +-- scripts/new-mcp-service.py
      |
      v
packages/mcp-common
      |
      +-- safe shared helpers
      +-- validation/contracts
      +-- path/HTTP helpers
      +-- reusable test patterns
```

Tekoda-internal reuse:

```text
mcp-lib (public reusable code)
          |
          v
tekoda-integrations (private adapters/façades)
          |
          +--> services/ssio-mcp
          +--> future Odoo/provider/product adapters
          |
          v
SSIO / Odoo / provider APIs / internal services
```

MCP is an agent-facing interface, **not** a bypass around the authoritative API, policy, approval or audit path.

## Start a new MCP service

The preferred path is now one command:

```bash
python scripts/new-mcp-service.py \
  --name proxmox \
  --contract flowoox.proxmox
```

This creates `services/proxmox-mcp` from [`templates/service-template`](templates/service-template/) and rewrites the package, project, CLI and contract identifiers automatically.

The generated service already provides:

- FastMCP with Streamable HTTP
- `get_capabilities`
- a versioned contract module
- typed Pydantic validation
- package/CLI structure
- a contract test
- an intentionally harmless read-only example capability

Then only the narrow upstream-specific client/handlers and their allow/deny tests need to be implemented. The scaffolder refuses to overwrite an existing target.

See [`docs/SERVER-KIT.md`](docs/SERVER-KIT.md).

## Images

```text
ghcr.io/flowoox/mcp-soulseek:0.3.1
ghcr.io/flowoox/mcp-spulseek:0.3.1  # compatibility alias for the historical typo
ghcr.io/flowoox/mcp-traxx:0.3.1
```

Versioned images are published only after lint, test, compile and container-build gates succeed on `main`.

## Contract families

Each service exposes a stable MCP contract through `get_capabilities`.

Current families:

```text
flowoox.music-acquisition v1.x
flowoox.music-library-import v1.x
```

Service/image versions and contract versions are separate. Additive tools and fields are compatible within a contract major; semantic breaks require a new major.

## Services

### Soulseek MCP

Wrapper for `slskd`. It configures the Soulseek account, web access and API key through MCP, manages the monitored `slskd.yml`, searches and scores complete album folders, groups `CD1`, `CD2`, `Disc 1` and similar subfolders and downloads a selected folder as one batch. Deterministic batch IDs and existing-batch checks make retries after timeouts/process interruption idempotent.

### Traxx MCP

Wrapper for Traxx/BeMusic 3.x. It uses the native TUS endpoint, metadata extraction and Artist/Album/Track APIs. Track and album artists remain distinct, guest artists are preserved and locally stored cover art is preferred to external hotlinks. A persistent import ledger prevents duplicate completed imports and keeps incomplete imports retryable.

## `packages/mcp-common`

This package is the seed for reusable MCP server helpers. New generally useful functionality should land here before being copied into multiple services.

Target responsibilities:

- capability discovery helpers
- typed input/output validation
- normalized errors
- correlation/request IDs
- timeout helpers
- optional idempotency helpers
- safe HTTP client primitives
- auth adapter interface
- policy/approval hook interface
- structured audit hook interface
- health/readiness helpers
- contract-test fixtures

The package must stay product-neutral and must not depend on private Tekoda services.

## Security model

- Tools are explicitly registered; there is no arbitrary shell/SQL/provider execution primitive.
- Model-supplied arguments are validated against typed schemas.
- Credentials are injected at runtime and never returned as tool output.
- Internal network reachability is not authorization.
- Writes may require upstream policy/approval and must preserve actor/correlation/idempotency context.
- A public MCP server must not require publishing private Tekoda network topology or customer data.

For SSIO-managed resources, the implemented Tekoda path is:

```text
MCP client -> tekoda-integrations/ssio-mcp -> SSIO typed API
           -> RBAC/policy/audit -> durable operation -> provider
```

not a direct provider bypass.

## Local development

```bash
docker compose -f compose.dev.yml up --build
```

Current local/internal endpoints:

```text
http://127.0.0.1:8081/mcp
http://127.0.0.1:8082/mcp
```

Each service owns its own `pyproject.toml`, Dockerfile, tests and runtime configuration. Shared product-neutral functionality belongs under `packages/mcp-common`.
