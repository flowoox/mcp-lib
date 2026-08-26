# FileShare MCP

`fileshare-mcp` is a product-neutral, bounded, read-only MCP service for Windows SMB/NTFS diagnostics. It is intended for administrators and diagnostic agents that need to understand paths and permissions without receiving a generic shell or unrestricted file-reading capability.

## Security model

The service is fail-closed. `FILESHARE_BACKEND_READ_ONLY=true` is an operator attestation and the Windows service account should independently be granted read-only rights. Every target must be expressed as `root_alias + relative_path`; callers cannot submit arbitrary drive or UNC paths. Root topology stays deployment-owned in `FILESHARE_ROOTS_JSON` and should not be committed to the public repository.

The backend exposes four fixed PowerShell operations only: path metadata, one-level directory listing, NTFS ACL observation and optional local SMB share ACL observation. There is no arbitrary command execution, recursive tree walk, file-content read, write, delete, rename, ownership/ACL modification or live watcher. Reparse points/junctions are blocked by default to reduce root-escape risk.

Each agent-facing operation carries a correlation ID, actor, reason, structured read-only audit envelope and a shared query budget limiting request count, fan-out, response bytes, item count and total execution time.

## Root configuration

Example only:

```text
FILESHARE_ROOTS_JSON=[{"alias":"data","path":"D:\\Shares\\Data","share_name":"Data"}]
FILESHARE_BACKEND_READ_ONLY=true
```

`share_name` is optional. When present, ACL diagnostics additionally call `Get-SmbShareAccess` on the local Windows host so the SMB share layer can be shown next to NTFS permissions.

## Tools

- `fileshare.roots.list`: return public aliases/descriptions without backend paths.
- `fileshare.path.observe`: bounded file/directory metadata and owner.
- `fileshare.directory.list`: immediate children only, hard page limit, never recursive.
- `fileshare.acl.observe`: normalized NTFS ACL plus optional SMB share ACL.
- `fileshare.access.explain`: conservative matching-ACE explanation for a supplied principal SID and already-resolved group SIDs.

`fileshare.access.explain` is deliberately **not** an authoritative Windows effective-access engine. It does not expand AD groups, simulate a Windows access token, privilege overrides, application-level checks, ACE canonicalization edge cases or conditional claims. Agents must preserve that distinction in diagnoses. AD membership resolution should come from `ad-mcp` and be passed in explicitly.

## Agent load safety

Directory listing is single-level and bounded. ACL lookups are at most two backend requests (NTFS and optional SMB share). File content is not exposed in v1. Agents should aggregate evidence first, then request detail only for the affected root/path rather than scanning entire servers.
