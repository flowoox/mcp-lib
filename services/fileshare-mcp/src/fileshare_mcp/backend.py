from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping
from typing import Any, Protocol

from .config import Settings

_ALLOWED_OPERATIONS = frozenset(
    {
        "path_info",
        "directory_list",
        "ntfs_acl",
        "share_acl",
        "file_hash",
        "text_preview",
        "text_search",
    }
)
_CONTENT_OPERATIONS = frozenset({"file_hash", "text_preview", "text_search"})

_COMMON_PREFIX = r"""
$ErrorActionPreference = 'Stop'
$path = $env:MCP_FILESHARE_PATH
if ([string]::IsNullOrWhiteSpace($path)) { throw 'path is required' }
$item = Get-Item -LiteralPath $path -Force
if ($env:MCP_FILESHARE_ALLOW_REPARSE -ne 'true') {
  $cursor = $item
  while ($null -ne $cursor) {
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw ('reparse point blocked: ' + $cursor.FullName)
    }
    $cursor = $cursor.Parent
  }
}
"""

_TEXT_FILE_PREFIX = _COMMON_PREFIX + r"""
if ($item.PSIsContainer) { throw 'text operation requires a regular file' }
$maxBytes = [int]$env:MCP_FILESHARE_MAX_BYTES
if ($maxBytes -lt 1) { throw 'invalid content byte limit' }
$readTarget = [int][Math]::Min([int64]$maxBytes, [int64]$item.Length)
$buffer = New-Object byte[] $readTarget
$stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
  $bytesRead = 0
  while ($bytesRead -lt $readTarget) {
    $count = $stream.Read($buffer, $bytesRead, $readTarget - $bytesRead)
    if ($count -le 0) { break }
    $bytesRead += $count
  }
} finally {
  $stream.Dispose()
}
$truncated = ([int64]$item.Length -gt [int64]$bytesRead)
for ($i = 0; $i -lt $bytesRead; $i++) {
  if ($buffer[$i] -eq 0) { throw 'binary content blocked: NUL byte detected' }
}
$utf8 = New-Object Text.UTF8Encoding($false, $true)
try {
  $text = $utf8.GetString($buffer, 0, $bytesRead)
} catch {
  throw 'text content must be valid UTF-8'
}
if ($text.StartsWith([char]0xFEFF)) { $text = $text.Substring(1) }
$maxChars = [int]$env:MCP_FILESHARE_MAX_CHARS
if ($text.Length -gt $maxChars) {
  $text = $text.Substring(0, $maxChars)
  $truncated = $true
}
"""

_SCRIPTS: Mapping[str, str] = {
    "path_info": _COMMON_PREFIX
    + r"""
$acl = Get-Acl -LiteralPath $item.FullName
[ordered]@{
  full_path = $item.FullName
  name = $item.Name
  exists = $true
  kind = $(if ($item.PSIsContainer) { 'directory' } else { 'file' })
  length = $(if ($item.PSIsContainer) { $null } else { [int64]$item.Length })
  last_write_time_utc = $item.LastWriteTimeUtc.ToString('o')
  attributes = @($item.Attributes.ToString().Split(',') | ForEach-Object { $_.Trim() })
  reparse_point = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
  owner = $acl.Owner
} | ConvertTo-Json -Depth 5 -Compress
""",
    "directory_list": _COMMON_PREFIX
    + r"""
if (-not $item.PSIsContainer) { throw 'directory_list requires a directory' }
$limit = [int]$env:MCP_FILESHARE_LIMIT
@(
  Get-ChildItem -LiteralPath $item.FullName -Force |
    Sort-Object Name |
    Select-Object -First $limit |
    ForEach-Object {
      [ordered]@{
        name = $_.Name
        kind = $(if ($_.PSIsContainer) { 'directory' } else { 'file' })
        length = $(if ($_.PSIsContainer) { $null } else { [int64]$_.Length })
        last_write_time_utc = $_.LastWriteTimeUtc.ToString('o')
        attributes = @($_.Attributes.ToString().Split(',') | ForEach-Object { $_.Trim() })
        reparse_point = (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
      }
    }
) | ConvertTo-Json -Depth 5 -Compress
""",
    "ntfs_acl": _COMMON_PREFIX
    + r"""
$acl = Get-Acl -LiteralPath $item.FullName
$aces = @($acl.Access | ForEach-Object {
  $sid = $null
  try { $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
  [ordered]@{
    identity = $_.IdentityReference.Value
    sid = $sid
    rights = $_.FileSystemRights.ToString()
    access_type = $_.AccessControlType.ToString()
    inherited = [bool]$_.IsInherited
    inheritance_flags = $_.InheritanceFlags.ToString()
    propagation_flags = $_.PropagationFlags.ToString()
  }
})
[ordered]@{
  full_path = $item.FullName
  owner = $acl.Owner
  inheritance_protected = [bool]$acl.AreAccessRulesProtected
  ntfs = $aces
  share = @()
} | ConvertTo-Json -Depth 6 -Compress
""",
    "share_acl": r"""
$ErrorActionPreference = 'Stop'
$name = $env:MCP_FILESHARE_SHARE_NAME
if ([string]::IsNullOrWhiteSpace($name)) { throw 'share name is required' }
@(
  Get-SmbShareAccess -Name $name | ForEach-Object {
    $sid = $null
    try { $sid = ([Security.Principal.NTAccount]$_.AccountName).Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
    [ordered]@{
      account_name = $_.AccountName
      sid = $sid
      access_type = $_.AccessControlType.ToString()
      access_right = $_.AccessRight.ToString()
    }
  }
) | ConvertTo-Json -Depth 5 -Compress
""",
    "file_hash": _COMMON_PREFIX
    + r"""
if ($item.PSIsContainer) { throw 'file_hash requires a regular file' }
$maxBytes = [int64]$env:MCP_FILESHARE_MAX_BYTES
if ($maxBytes -lt 1) { throw 'invalid hash byte limit' }
if ([int64]$item.Length -gt $maxBytes) { throw 'file exceeds configured hash byte limit' }
$stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
$sha = [Security.Cryptography.SHA256]::Create()
$buffer = New-Object byte[] 65536
$total = [int64]0
try {
  while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
    $total += $count
    if ($total -gt $maxBytes) { throw 'file exceeded configured hash byte limit while reading' }
    [void]$sha.TransformBlock($buffer, 0, $count, $buffer, 0)
  }
  [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
  $digest = -join ($sha.Hash | ForEach-Object { $_.ToString('x2') })
} finally {
  $sha.Dispose()
  $stream.Dispose()
}
[ordered]@{
  algorithm = 'sha256'
  digest = $digest
  length = [int64]$item.Length
  bytes_read = $total
} | ConvertTo-Json -Depth 4 -Compress
""",
    "text_preview": _TEXT_FILE_PREFIX
    + r"""
$maxLines = [int]$env:MCP_FILESHARE_MAX_LINES
$lines = @($text -split '\r?\n')
if ($lines.Count -gt $maxLines) {
  $lines = @($lines | Select-Object -First $maxLines)
  $truncated = $true
}
$preview = [string]::Join("`n", $lines)
[ordered]@{
  encoding = 'utf-8'
  bytes_read = $bytesRead
  decoded_characters = $text.Length
  lines_returned = $lines.Count
  truncated = [bool]$truncated
  preview = $preview
} | ConvertTo-Json -Depth 4 -Compress
""",
    "text_search": _TEXT_FILE_PREFIX
    + r"""
$query = $env:MCP_FILESHARE_QUERY
if ([string]::IsNullOrWhiteSpace($query)) { throw 'search query is required' }
$caseSensitive = ($env:MCP_FILESHARE_CASE_SENSITIVE -eq 'true')
$comparison = $(if ($caseSensitive) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase })
$maxLines = [int]$env:MCP_FILESHARE_MAX_LINES
$maxMatches = [int]$env:MCP_FILESHARE_MAX_MATCHES
$maxSnippet = [int]$env:MCP_FILESHARE_MAX_SNIPPET_CHARS
$allLines = @($text -split '\r?\n')
$scanLines = @($allLines | Select-Object -First $maxLines)
if ($allLines.Count -gt $scanLines.Count) { $truncated = $true }
$matches = @()
for ($lineIndex = 0; $lineIndex -lt $scanLines.Count; $lineIndex++) {
  $line = [string]$scanLines[$lineIndex]
  $matchIndex = $line.IndexOf($query, $comparison)
  if ($matchIndex -lt 0) { continue }
  $snippet = $line
  if ($snippet.Length -gt $maxSnippet) {
    $start = [Math]::Max(0, [Math]::Min($matchIndex - [int]($maxSnippet / 3), $snippet.Length - $maxSnippet))
    $snippet = $snippet.Substring($start, $maxSnippet)
  }
  $matches += [ordered]@{ line_number = $lineIndex + 1; snippet = $snippet }
  if ($matches.Count -ge $maxMatches) {
    $truncated = $true
    break
  }
}
[ordered]@{
  encoding = 'utf-8'
  bytes_read = $bytesRead
  decoded_characters = $text.Length
  lines_scanned = $scanLines.Count
  truncated = [bool]$truncated
  matches = @($matches)
} | ConvertTo-Json -Depth 5 -Compress
""",
}


class FileShareBackend(Protocol):
    async def execute(
        self,
        operation: str,
        *,
        path: str = "",
        share_name: str = "",
        limit: int = 0,
        max_bytes: int = 0,
        max_chars: int = 0,
        max_lines: int = 0,
        max_matches: int = 0,
        max_snippet_chars: int = 0,
        query: str = "",
        case_sensitive: bool = False,
        timeout_seconds: float,
    ) -> Any: ...


class PowerShellFileShareBackend:
    """Fixed-command, read-only PowerShell adapter for a Windows file server."""

    def __init__(self, settings: Settings) -> None:
        if not settings.fileshare_backend_read_only:
            raise RuntimeError("FILESHARE_BACKEND_READ_ONLY=true is required")
        self.settings = settings

    async def execute(
        self,
        operation: str,
        *,
        path: str = "",
        share_name: str = "",
        limit: int = 0,
        max_bytes: int = 0,
        max_chars: int = 0,
        max_lines: int = 0,
        max_matches: int = 0,
        max_snippet_chars: int = 0,
        query: str = "",
        case_sensitive: bool = False,
        timeout_seconds: float,
    ) -> Any:
        if operation not in _ALLOWED_OPERATIONS:
            raise ValueError("operation is not allowlisted")
        if operation in _CONTENT_OPERATIONS and not self.settings.fileshare_content_read_enabled:
            raise RuntimeError("FILESHARE_CONTENT_READ_ENABLED=true is required for content analysis")
        if sys.platform != "win32":
            raise RuntimeError("fileshare PowerShell backend requires Windows")
        env = os.environ.copy()
        env["MCP_FILESHARE_PATH"] = path
        env["MCP_FILESHARE_SHARE_NAME"] = share_name
        env["MCP_FILESHARE_LIMIT"] = str(limit)
        env["MCP_FILESHARE_MAX_BYTES"] = str(max_bytes)
        env["MCP_FILESHARE_MAX_CHARS"] = str(max_chars)
        env["MCP_FILESHARE_MAX_LINES"] = str(max_lines)
        env["MCP_FILESHARE_MAX_MATCHES"] = str(max_matches)
        env["MCP_FILESHARE_MAX_SNIPPET_CHARS"] = str(max_snippet_chars)
        env["MCP_FILESHARE_QUERY"] = query
        env["MCP_FILESHARE_CASE_SENSITIVE"] = "true" if case_sensitive else "false"
        env["MCP_FILESHARE_ALLOW_REPARSE"] = (
            "true" if self.settings.fileshare_allow_reparse_points else "false"
        )
        process = await asyncio.create_subprocess_exec(
            self.settings.fileshare_powershell_executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _SCRIPTS[operation],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("fileshare backend command timed out") from None
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()[:500]
            raise RuntimeError(f"fileshare backend command failed: {detail or 'unknown error'}")
        if len(stdout) > self.settings.fileshare_max_response_bytes:
            raise RuntimeError("fileshare backend response exceeded configured byte limit")
        text = stdout.decode("utf-8-sig", errors="strict").strip()
        if not text:
            return [] if operation in {"directory_list", "share_acl"} else {}
        return json.loads(text)
