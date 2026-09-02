# FileShare MCP

`fileshare-mcp` is a product-neutral, bounded, read-only MCP service for Windows SMB/NTFS diagnostics. It is intended for administrators and diagnostic agents that need to understand paths and permissions without receiving a generic shell or unrestricted file-reading capability.

## Security model

The service is fail-closed. `FILESHARE_BACKEND_READ_ONLY=true` is an operator attestation and the Windows service account should independently be granted read-only rights. Every target must be expressed as `root_alias + relative_path`; callers cannot submit arbitrary drive or UNC paths. Root topology stays deployment-owned in `FILESHARE_ROOTS_JSON` and should not be committed to the public repository.

The base backend exposes fixed PowerShell operations only: path metadata, one-level directory listing, NTFS ACL observation and optional local SMB share ACL observation. There is no arbitrary command execution, recursive tree walk, write, delete, rename, ownership/ACL modification or live watcher. Reparse points/junctions are blocked by default to reduce root-escape risk. Relative paths additionally reject traversal, drive/device paths, alternate data streams, reserved Windows device names and canonicalization-ambiguous trailing spaces/dots.

Each agent-facing operation carries a correlation ID, actor, reason, structured read-only audit envelope and a shared query budget limiting request count, fan-out, response bytes, item count and total execution time.

## Root configuration

Example only:

```text
FILESHARE_ROOTS_JSON=[{"alias":"data","path":"D:\\Shares\\Data","share_name":"Data","content_read":false}]
FILESHARE_BACKEND_READ_ONLY=true
```

`share_name` is optional. When present, ACL diagnostics additionally call `Get-SmbShareAccess` on the local Windows host so the SMB share layer can be shown next to NTFS permissions. Physical paths remain deployment-owned and are never returned by `fileshare.roots.list`.

## Optional bounded content analysis

Content analysis is disabled by default and is intentionally a separate, double-opt-in capability. It becomes available only when all of the following are true:

1. `FILESHARE_BACKEND_READ_ONLY=true`.
2. `FILESHARE_CONTENT_READ_ENABLED=true`.
3. The selected root has `"content_read": true`.
4. Text preview/search targets use an extension from `FILESHARE_SAFE_TEXT_EXTENSIONS`.

The default text allowlist is `.txt,.log,.csv,.json,.xml,.yaml,.yml,.md,.ini,.conf,.cfg`. Deployments may narrow it further. Text content must be valid UTF-8 and is rejected when a NUL byte is detected. Regex, recursive content search, arbitrary encodings, binary preview, whole-file streaming and arbitrary path access are not implemented.

Hard default ceilings are 64 KiB source bytes per text operation, 32,768 decoded characters, 400 lines, 20 search matches, 240 characters per returned match snippet and 32 MiB per SHA-256 hash operation. Backends return `bytes_read`, and the server validates those values against the configured source-read ceilings before exposing the result. QueryBudget separately bounds downstream requests, fan-out, response bytes, item counts and total elapsed time.

SHA-256 hashing may target any regular file under an opted-in root, but the file is rejected when it exceeds `FILESHARE_MAX_HASH_BYTES`; only the digest, length and accounted bytes read are returned. Text search is literal substring matching only and is bounded by the same byte/character/line ceilings as preview.

## Tools

- `fileshare.roots.list`: return public aliases/descriptions without backend paths, including whether bounded content analysis is enabled for the alias.
- `fileshare.path.observe`: bounded file/directory metadata and owner.
- `fileshare.directory.list`: immediate children only, hard page limit, never recursive.
- `fileshare.acl.observe`: normalized NTFS ACL plus optional SMB share ACL.
- `fileshare.access.explain`: conservative matching-ACE explanation for a supplied principal SID and already-resolved group SIDs.
- `fileshare.file.hash`: optional bounded SHA-256 calculation for one regular file under a content-enabled root.
- `fileshare.text.preview`: optional bounded UTF-8 text preview for one allowlisted text file.
- `fileshare.text.search`: optional bounded literal substring search returning limited line snippets only.

The three content tools are not registered when `FILESHARE_CONTENT_READ_ENABLED=false`, and they are omitted from the advertised capability list in that state.

`fileshare.access.explain` is deliberately **not** an authoritative Windows effective-access engine. It does not expand AD groups, simulate a Windows access token, privilege overrides, application-level checks, ACE canonicalization edge cases or conditional claims. Agents must preserve that distinction in diagnoses. AD membership resolution should come from `ad-mcp` and be passed in explicitly.

## Agent load safety

Directory listing is single-level and bounded. ACL lookups are at most two backend requests (NTFS and optional SMB share). Content operations always target one explicitly named file; there is no recursive enumeration or multi-file fan-out. Agents should aggregate evidence first, then request detail only for the affected root/path rather than scanning entire servers.
