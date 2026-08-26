from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping
from typing import Any, Protocol

from .config import Settings

_ALLOWED_OPERATIONS = frozenset({"path_info", "directory_list", "ntfs_acl", "share_acl"})

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
}


class FileShareBackend(Protocol):
    async def execute(
        self,
        operation: str,
        *,
        path: str = "",
        share_name: str = "",
        limit: int = 0,
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
        timeout_seconds: float,
    ) -> Any:
        if operation not in _ALLOWED_OPERATIONS:
            raise ValueError("operation is not allowlisted")
        if sys.platform != "win32":
            raise RuntimeError("fileshare PowerShell backend requires Windows")
        env = os.environ.copy()
        env["MCP_FILESHARE_PATH"] = path
        env["MCP_FILESHARE_SHARE_NAME"] = share_name
        env["MCP_FILESHARE_LIMIT"] = str(limit)
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
