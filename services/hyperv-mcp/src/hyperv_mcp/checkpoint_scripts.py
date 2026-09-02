from __future__ import annotations

from enum import StrEnum


class CheckpointScriptId(StrEnum):
    PREFLIGHT = "checkpoint-preflight"
    CREATE = "checkpoint-create"


_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$rawInput = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_INPUT')
if ([string]::IsNullOrWhiteSpace($rawInput)) { throw 'Checkpoint operation requires structured input' }
$inputData = $rawInput | ConvertFrom-Json -ErrorAction Stop
"""


def _script(body: str) -> str:
    return _PREAMBLE + "\n" + body.strip() + "\n"


_PREFLIGHT_BODY = r"""
$vmName = [string]$inputData.vmName
$maxExisting = [int]$inputData.maxExisting
if ([string]::IsNullOrWhiteSpace($vmName) -or $vmName.Length -gt 256) { throw 'Invalid VM name' }
if ($maxExisting -lt 1 -or $maxExisting -gt 32) { throw 'Invalid checkpoint-count limit' }
$vms = @(Get-VM -Name $vmName -ErrorAction Stop)
if ($vms.Count -ne 1 -or -not [string]::Equals([string]$vms[0].Name, $vmName, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'VM name did not resolve to exactly one VM'
}
$vm = $vms[0]
$all = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Sort-Object -Property CreationTime)
$evidence = @($all | Select-Object -First 64 | ForEach-Object {
  [ordered]@{
    id = [string]$_.Id
    name = [string]$_.Name
    snapshotType = [string]$_.SnapshotType
    creationTime = ([datetime]$_.CreationTime).ToUniversalTime().ToString('o')
  }
})
[ordered]@{
  items = @([ordered]@{
    vmId = [string]$vm.Id
    vmName = [string]$vm.Name
    state = [string]$vm.State
    status = [string]$vm.Status
    clustered = [bool]$vm.IsClustered
    checkpointType = [string]$vm.CheckpointType
    checkpointCount = [int]$all.Count
    checkpoints = $evidence
    checkpointsTruncated = [bool]($all.Count -gt $evidence.Count)
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 8 -Compress
"""


CHECKPOINT_SCRIPTS: dict[CheckpointScriptId, str] = {
    CheckpointScriptId.PREFLIGHT: _script(_PREFLIGHT_BODY),
    CheckpointScriptId.CREATE: _script(
        r"""
$vmName = [string]$inputData.vmName
$expectedVmId = [guid]([string]$inputData.expectedVmId)
$snapshotName = [string]$inputData.snapshotName
$maxExisting = [int]$inputData.maxExisting
if ([string]::IsNullOrWhiteSpace($vmName) -or $vmName.Length -gt 256) { throw 'Invalid VM name' }
if ($snapshotName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$') { throw 'Invalid checkpoint name' }
if ($maxExisting -lt 1 -or $maxExisting -gt 32) { throw 'Invalid checkpoint-count limit' }
$vms = @(Get-VM -Name $vmName -ErrorAction Stop)
if ($vms.Count -ne 1 -or -not [string]::Equals([string]$vms[0].Name, $vmName, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'VM name did not resolve to exactly one VM'
}
$vm = $vms[0]
if ($vm.Id -ne $expectedVmId) { throw 'VM identity changed after approval' }
if ([string]$vm.CheckpointType -ne 'ProductionOnly') {
  throw 'Automated checkpoint creation requires CheckpointType=ProductionOnly'
}
$state = [string]$vm.State
if ($state -ne 'Running' -and $state -ne 'Off') {
  throw 'VM must be Running or Off before checkpoint creation'
}
$all = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
$existing = @($all | Where-Object { [string]::Equals([string]$_.Name, $snapshotName, [System.StringComparison]::Ordinal) })
if ($existing.Count -gt 1) { throw 'Multiple checkpoints already use the deterministic checkpoint name' }
if ($existing.Count -eq 0 -and $all.Count -ge $maxExisting) {
  throw 'Existing checkpoint count reached the configured safety limit'
}
$changed = $false
if ($existing.Count -eq 0) {
  Checkpoint-VM -VM $vm -SnapshotName $snapshotName -Confirm:$false -ErrorAction Stop | Out-Null
  $changed = $true
}
$readback = @(Get-VMSnapshot -VM $vm -ErrorAction Stop | Where-Object { [string]::Equals([string]$_.Name, $snapshotName, [System.StringComparison]::Ordinal) })
if ($readback.Count -ne 1) { throw 'Checkpoint readback did not resolve exactly one checkpoint' }
$checkpoint = $readback[0]
[ordered]@{
  items = @([ordered]@{
    changed = $changed
    vmId = [string]$vm.Id
    vmName = [string]$vm.Name
    checkpointId = [string]$checkpoint.Id
    checkpointName = [string]$checkpoint.Name
    snapshotType = [string]$checkpoint.SnapshotType
    creationTime = ([datetime]$checkpoint.CreationTime).ToUniversalTime().ToString('o')
    checkpointType = [string]$vm.CheckpointType
    clustered = [bool]$vm.IsClustered
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 7 -Compress
"""
    ),
}
