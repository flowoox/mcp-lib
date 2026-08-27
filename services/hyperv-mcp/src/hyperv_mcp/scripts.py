from __future__ import annotations

from enum import StrEnum


class ScriptId(StrEnum):
    HOST = "host"
    VMS = "vms"
    VM_DETAIL = "vm-detail"
    SWITCHES = "switches"
    CHECKPOINTS = "checkpoints"
    VHDS = "vhds"
    REPLICATION = "replication"
    EVENTS = "events"


_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$rawInput = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_INPUT')
if ([string]::IsNullOrWhiteSpace($rawInput)) { $inputData = [pscustomobject]@{} }
else { $inputData = $rawInput | ConvertFrom-Json }
"""


def _script(body: str) -> str:
    return _PREAMBLE + "\n" + body.strip() + "\n"


SCRIPTS: dict[ScriptId, str] = {
    ScriptId.HOST: _script(
        r"""
if (-not (Get-Command -Name Get-VMHost -ErrorAction SilentlyContinue)) {
  [ordered]@{
    items = @([ordered]@{
      computerName = [string][Environment]::MachineName
      available = $false
      vmCounts = @{}
      migrationEnabled = $false
      logicalProcessors = 0
      memoryCapacityBytes = 0
      memoryAssignedBytes = 0
      memoryAssignedPercent = 0.0
    })
    nextCursor = $null
  } | ConvertTo-Json -Depth 6 -Compress
  return
}
$hostInfo = Get-VMHost -ErrorAction Stop
$vms = @(Get-VM -ErrorAction Stop)
$counts = @{}
foreach ($group in @($vms | Group-Object -Property State)) {
  $counts[[string]$group.Name] = [int]$group.Count
}
$assigned = [int64]0
foreach ($vm in $vms) { $assigned += [int64]$vm.MemoryAssigned }
$capacity = [int64]$hostInfo.MemoryCapacity
$assignedPercent = if ($capacity -gt 0) { [math]::Round(($assigned * 100.0) / $capacity, 2) } else { 0.0 }
$migrationEnabled = $false
try { $migrationEnabled = [bool]$hostInfo.VirtualMachineMigrationEnabled } catch {}
[ordered]@{
  items = @([ordered]@{
    computerName = [string][Environment]::MachineName
    available = $true
    vmCounts = $counts
    migrationEnabled = $migrationEnabled
    logicalProcessors = [int]$hostInfo.LogicalProcessorCount
    memoryCapacityBytes = $capacity
    memoryAssignedBytes = $assigned
    memoryAssignedPercent = [double]$assignedPercent
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.VMS: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$all = @(Get-VM -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    id = [string]$_.Id
    name = [string]$_.Name
    state = [string]$_.State
    status = [string]$_.Status
    generation = [int]$_.Generation
    version = [string]$_.Version
    uptimeSeconds = [math]::Max(0, [int64]$_.Uptime.TotalSeconds)
    cpuUsagePercent = [math]::Max(0, [int]$_.CPUUsage)
    memoryAssignedBytes = [math]::Max(0, [int64]$_.MemoryAssigned)
    memoryDemandBytes = [math]::Max(0, [int64]$_.MemoryDemand)
    processorCount = [math]::Max(0, [int]$_.ProcessorCount)
    clustered = [bool]$_.IsClustered
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.VM_DETAIL: _script(
        r"""
$vmName = [string]$inputData.vmName
$vm = Get-VM -Name $vmName -ErrorAction Stop
$adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop | Select-Object -First 32 | ForEach-Object {
  [ordered]@{
    name = [string]$_.Name
    switchName = if ([string]::IsNullOrWhiteSpace([string]$_.SwitchName)) { $null } else { [string]$_.SwitchName }
    macAddress = [string]$_.MacAddress
    status = [string]$_.Status
    ipAddresses = @($_.IPAddresses | Select-Object -First 32 | ForEach-Object { [string]$_ })
  }
})
$services = @(Get-VMIntegrationService -VM $vm -ErrorAction Stop | Select-Object -First 32 | ForEach-Object {
  [ordered]@{
    name = [string]$_.Name
    enabled = [bool]$_.Enabled
    primaryStatus = [string]$_.PrimaryStatusDescription
    secondaryStatus = [string]$_.SecondaryStatusDescription
  }
})
$checkpointCount = @(Get-VMSnapshot -VM $vm -ErrorAction Stop).Count
[ordered]@{
  items = @([ordered]@{
    id = [string]$vm.Id
    name = [string]$vm.Name
    state = [string]$vm.State
    status = [string]$vm.Status
    generation = [int]$vm.Generation
    version = [string]$vm.Version
    uptimeSeconds = [math]::Max(0, [int64]$vm.Uptime.TotalSeconds)
    cpuUsagePercent = [math]::Max(0, [int]$vm.CPUUsage)
    memoryAssignedBytes = [math]::Max(0, [int64]$vm.MemoryAssigned)
    memoryDemandBytes = [math]::Max(0, [int64]$vm.MemoryDemand)
    processorCount = [math]::Max(0, [int]$vm.ProcessorCount)
    clustered = [bool]$vm.IsClustered
    automaticStartAction = [string]$vm.AutomaticStartAction
    automaticStopAction = [string]$vm.AutomaticStopAction
    checkpointCount = [int]$checkpointCount
    networkAdapters = $adapters
    integrationServices = $services
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 8 -Compress
"""
    ),
    ScriptId.SWITCHES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$all = @(Get-VMSwitch -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $allowManagementOS = $null
  $embeddedTeamingEnabled = $null
  $iovEnabled = $null
  try { $allowManagementOS = [bool]$_.AllowManagementOS } catch {}
  try { $embeddedTeamingEnabled = [bool]$_.EmbeddedTeamingEnabled } catch {}
  try { $iovEnabled = [bool]$_.IovEnabled } catch {}
  [ordered]@{
    id = [string]$_.Id
    name = [string]$_.Name
    switchType = [string]$_.SwitchType
    netAdapterInterfaceDescription = if ([string]::IsNullOrWhiteSpace([string]$_.NetAdapterInterfaceDescription)) { $null } else { [string]$_.NetAdapterInterfaceDescription }
    allowManagementOS = $allowManagementOS
    embeddedTeamingEnabled = $embeddedTeamingEnabled
    iovEnabled = $iovEnabled
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.CHECKPOINTS: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$vmName = [string]$inputData.vmName
$all = @(Get-VMSnapshot -VMName $vmName -ErrorAction Stop | Sort-Object -Property CreationTime -Descending)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    id = [string]$_.Id
    vmName = [string]$_.VMName
    name = [string]$_.Name
    snapshotType = [string]$_.SnapshotType
    creationTime = ([datetime]$_.CreationTime).ToUniversalTime().ToString('o')
    parentSnapshotName = if ($null -eq $_.ParentSnapshot) { $null } else { [string]$_.ParentSnapshot.Name }
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.VHDS: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$vmName = [string]$inputData.vmName
$all = @(Get-VMHardDiskDrive -VMName $vmName -ErrorAction Stop | Sort-Object -Property ControllerType, ControllerNumber, ControllerLocation)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $vhd = $null
  try { $vhd = Get-VHD -Path $_.Path -ErrorAction Stop } catch {}
  [ordered]@{
    vmName = $vmName
    path = [string]$_.Path
    controllerType = [string]$_.ControllerType
    controllerNumber = [int]$_.ControllerNumber
    controllerLocation = [int]$_.ControllerLocation
    vhdType = if ($null -eq $vhd) { $null } else { [string]$vhd.VhdType }
    vhdFormat = if ($null -eq $vhd) { $null } else { [string]$vhd.VhdFormat }
    sizeBytes = if ($null -eq $vhd) { $null } else { [int64]$vhd.Size }
    fileSizeBytes = if ($null -eq $vhd) { $null } else { [int64]$vhd.FileSize }
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.REPLICATION: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$vmName = [string]$inputData.vmName
if ([string]::IsNullOrWhiteSpace($vmName)) {
  $all = @(Get-VMReplication -ErrorAction Stop | Sort-Object -Property VMName)
} else {
  $all = @(Get-VMReplication -VMName $vmName -ErrorAction SilentlyContinue | Sort-Object -Property VMName)
}
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $last = $null
  try {
    if ($null -ne $_.LastReplicationTime) { $last = ([datetime]$_.LastReplicationTime).ToUniversalTime().ToString('o') }
  } catch {}
  $frequency = $null
  try {
    if ($null -ne $_.ReplicationFrequencySec) { $frequency = [int]$_.ReplicationFrequencySec }
  } catch {}
  [ordered]@{
    vmName = [string]$_.VMName
    state = [string]$_.State
    health = [string]$_.Health
    mode = [string]$_.Mode
    primaryServer = [string]$_.PrimaryServer
    replicaServer = [string]$_.ReplicaServer
    lastReplicationTime = $last
    frequencySeconds = $frequency
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.EVENTS: _script(
        r"""
$limit = [int]$inputData.limit
$logId = [string]$inputData.logId
$lookback = [int]$inputData.lookbackMinutes
$level = [string]$inputData.level
$includeMessage = [bool]$inputData.includeMessage
$logs = @{
  'vmms' = 'Microsoft-Windows-Hyper-V-VMMS/Admin'
  'worker' = 'Microsoft-Windows-Hyper-V-Worker-Admin'
}
$logName = $logs[$logId]
if ([string]::IsNullOrWhiteSpace($logName)) { throw 'Unsupported Hyper-V event log ID' }
$start = (Get-Date).AddMinutes(-1 * $lookback)
$filter = @{ LogName = $logName; StartTime = $start }
if ($level -eq 'critical') { $filter.Level = 1 }
elseif ($level -eq 'error') { $filter.Level = 2 }
elseif ($level -eq 'warning') { $filter.Level = 3 }
$events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $limit -ErrorAction Stop)
$items = @($events | ForEach-Object {
  $preview = $null
  if ($includeMessage) {
    $message = [string]$_.Message
    if ($message.Length -gt 512) { $message = $message.Substring(0, 512) }
    $preview = $message -replace '[\r\n]+', ' '
  }
  [ordered]@{
    recordId = [int64]$_.RecordId
    eventId = [int]$_.Id
    level = [string]$_.LevelDisplayName
    providerName = [string]$_.ProviderName
    timeCreated = if ($null -eq $_.TimeCreated) { $null } else { ([datetime]$_.TimeCreated).ToUniversalTime().ToString('o') }
    messagePreview = $preview
  }
})
[ordered]@{ items = $items; nextCursor = $null } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
}
