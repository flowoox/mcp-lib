# Freshdesk MCP

Product-neutral, bounded **read-only** Freshdesk diagnostics for agents and n8n workflows. Observe v1 deliberately exposes only fixed Freshdesk API v2 GET operations and projects responses into typed, minimized diagnostic records.

## Security model

The service fails closed unless `FRESHDESK_BACKEND_READ_ONLY=true` and both the helpdesk origin and API key are configured. That flag is an operator attestation, not a substitute for Freshdesk permissions: use a dedicated Freshdesk agent/API key whose role can only view the ticket scope required by the deployment. Freshdesk API authorization follows the permissions of the user profile behind the API key, so do not deploy this MCP with a personal administrator key.

The public MCP surface never accepts an arbitrary URL, HTTP method or Freshdesk search DSL. It does not register create/update/delete/reply/note/forward/merge/restore operations. Requester IDs, requester contact data, responder/agent IDs, company IDs, conversation email addresses, message bodies, structured bodies, custom fields and attachment contents are excluded from public projections. Attachment data is reduced to a count. Ticket subjects remain available, bounded to 256 characters, because they are operational ticket metadata and may themselves contain user-entered text; deployments that require stricter content minimization should restrict the Freshdesk reader role to the necessary groups/tickets.

All reads are wrapped in `ReadOnlyConnector` and `QueryBudget` controls: explicit operation allowlisting, page and sample caps, bounded response bytes, timeout, concurrency, rate limiting, total request/item/fan-out budgets, caching hints and aggregate-before-fan-out behavior. HTTP redirects are rejected. Freshdesk `429` responses are surfaced without automatic retry, preventing an agent from amplifying an account-wide rate-limit event.

## Observe v1 operations

- `freshdesk.tickets.list`: recent/listed tickets using only Freshdesk's fixed predefined filters plus bounded `updated_since` and safe sort fields. Generic search queries and requester-email filters are not exposed.
- `freshdesk.tickets.get`: one exact decimal ticket ID, projected without description/body/requester/agent data.
- `freshdesk.tickets.conversations`: bounded conversation metadata for one exact ticket. Bodies and addresses are discarded; only direction/privacy/source/timestamps, body-presence/length and attachment count are returned.
- `freshdesk.diagnostics.bundle`: server-side aggregate-first ticket + recent conversation metadata with a small conversation summary. It is an MCP composition, not an additional backend API endpoint.

Every tool response uses the shared typed operation/audit envelope and includes actor, correlation ID, read-only risk classification and remaining query-budget state.

## Freshdesk API assumptions

Observe v1 targets the documented Freshdesk API v2 over HTTPS. Freshdesk documents API-key Basic authentication (`apikey:X`), authorization based on the Freshdesk user profile, list pagination via `page`/`per_page` with a maximum page size of 100, `Link` next-page headers and account-wide rate limits. The adapter intentionally uses only the documented ticket and ticket-conversation GET endpoints and never uses response `include` expansions.

Freshdesk also documents that list-ticket calls return only recent tickets by default and accept `updated_since`; the MCP exposes that parameter but caps page depth independently with `FRESHDESK_MAX_PAGE_NUMBER` (default 50) to avoid deep pagination and agent-driven full-helpdesk scans.

## Deployment

Copy `.env.example` to a deployment-owned secret environment file and provide only the Freshdesk origin, never `/api/v2` and never credentials in the URL. Set `FRESHDESK_BACKEND_READ_ONLY=true` only after verifying the API key's Freshdesk role is view-only for the required ticket scope. Keep URLs, keys, group mappings, company policy and any tenant-specific routing outside this public repository.

The example container runs as UID/GID 10001, drops Linux capabilities, uses a read-only root filesystem and binds to loopback by default. External MCP exposure still requires the repository's MCP transport/auth controls or an authenticated reverse proxy.
