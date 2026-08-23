from __future__ import annotations

from enum import StrEnum


class ScriptId(StrEnum):
    HOST = "host"
    SERVICES = "services"
    PROCESSES = "processes"
    FEATURES = "features"
    EVENTS = "events"
    CERTIFICATES = "certificates"
    UPDATES = "updates"
    HYPERV_HOST = "hyperv-host"


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
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$boot = [datetime]$os.LastBootUpTime
$uptime = [math]::Max(0, [int64]([datetime]::UtcNow - $boot.ToUniversalTime()).TotalSeconds)
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
           (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations')
$result = [ordered]@{
  items = @([ordered]@{
    computerName = [string][Environment]::MachineName
    osCaption = [string]$os.Caption
    osVersion = [string]$os.Version
    buildNumber = [string]$os.BuildNumber
    lastBootTime = $boot.ToUniversalTime().ToString('o')
    uptimeSeconds = $uptime
    totalMemoryBytes = [int64]$cs.TotalPhysicalMemory
    logicalProcessors = [int]$cs.NumberOfLogicalProcessors
    domainRole = [int]$cs.DomainRole
    rebootPending = [bool]$pending
  })
  nextCursor = $null
}
$result | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.SERVICES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$state = [string]$inputData.state
$all = @(Get-Service | Sort-Object -Property Name)
if ($state -eq 'running') { $all = @($all | Where-Object { $_.Status -eq 'Running' }) }
elseif ($state -eq 'stopped') { $all = @($all | Where-Object { $_.Status -eq 'Stopped' }) }
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    name = [string]$_.Name
    displayName = [string]$_.DisplayName
    status = [string]$_.Status
    startType = [string]$_.StartType
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.PROCESSES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$sortBy = [string]$inputData.sortBy
$rows = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
  $cpu = $null
  try { if ($null -ne $_.CPU) { $cpu = [double]$_.CPU } } catch {}
  [pscustomobject]@{
    processName = [string]$_.ProcessName
    processId = [int]$_.Id
    cpuSeconds = $cpu
    workingSetBytes = [int64]$_.WorkingSet64
  }
})
if ($sortBy -eq 'cpu') { $all = @($rows | Sort-Object -Property @{Expression={ if ($null -eq $_.cpuSeconds) { -1 } else { $_.cpuSeconds } }; Descending=$true}, processName, processId) }
elseif ($sortBy -eq 'name') { $all = @($rows | Sort-Object -Property processName, processId) }
else { $all = @($rows | Sort-Object -Property workingSetBytes -Descending) }
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    processName = [string]$_.processName
    processId = [int]$_.processId
    cpuSeconds = $_.cpuSeconds
    workingSetBytes = [int64]$_.workingSetBytes
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.FEATURES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$installedOnly = [bool]$inputData.installedOnly
if (-not (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue)) {
  throw 'Get-WindowsFeature is unavailable on this target'
}
$all = @(Get-WindowsFeature | Sort-Object -Property Name)
if ($installedOnly) { $all = @($all | Where-Object { $_.Installed }) }
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    name = [string]$_.Name
    displayName = [string]$_.DisplayName
    installed = [bool]$_.Installed
    installState = [string]$_.InstallState
    restartNeeded = [string]$_.RestartNeeded
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.EVENTS: _script(
        r"""
$limit = [int]$inputData.limit
$logName = [string]$inputData.logName
$lookback = [int]$inputData.lookbackMinutes
$level = [string]$inputData.level
$includeMessage = [bool]$inputData.includeMessage
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
[ordered]@{ items = $items; nextCursor = $null } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.CERTIFICATES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$storeId = [string]$inputData.storeId
$withinDays = $inputData.expiringWithinDays
$paths = @{
  'machine-my' = 'Cert:\LocalMachine\My'
  'machine-root' = 'Cert:\LocalMachine\Root'
  'machine-ca' = 'Cert:\LocalMachine\CA'
}
$path = $paths[$storeId]
if ([string]::IsNullOrWhiteSpace($path)) { throw 'Unsupported certificate store ID' }
$all = @(Get-ChildItem -Path $path -ErrorAction Stop | Sort-Object -Property NotAfter)
if ($null -ne $withinDays) {
  $cutoff = (Get-Date).AddDays([int]$withinDays)
  $all = @($all | Where-Object { $_.NotAfter -le $cutoff })
}
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  [ordered]@{
    thumbprint = [string]$_.Thumbprint
    subject = [string]$_.Subject
    issuer = [string]$_.Issuer
    notBefore = ([datetime]$_.NotBefore).ToUniversalTime().ToString('o')
    notAfter = ([datetime]$_.NotAfter).ToUniversalTime().ToString('o')
    hasPrivateKey = [bool]$_.HasPrivateKey
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.UPDATES: _script(
        r"""
$limit = [int]$inputData.limit
$offset = [int]$inputData.offset
$all = @(Get-HotFix | Sort-Object -Property InstalledOn -Descending)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $installed = $null
  if ($_.InstalledOn -is [datetime]) { $installed = ([datetime]$_.InstalledOn).ToUniversalTime().ToString('o') }
  [ordered]@{
    hotFixId = [string]$_.HotFixID
    description = [string]$_.Description
    installedOn = $installed
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 5 -Compress
"""
    ),
    ScriptId.HYPERV_HOST: _script(
        r"""
if (-not (Get-Command -Name Get-VMHost -ErrorAction SilentlyContinue)) {
  [ordered]@{ items = @([ordered]@{ available = $false; vmCounts = @{}; migrationEnabled = $false }); nextCursor = $null } | ConvertTo-Json -Depth 6 -Compress
  return
}
$hostInfo = Get-VMHost -ErrorAction Stop
$vms = @(Get-VM -ErrorAction Stop)
$counts = @{}
foreach ($group in @($vms | Group-Object -Property State)) { $counts[[string]$group.Name] = [int]$group.Count }
[ordered]@{
  items = @([ordered]@{
    available = $true
    vmCounts = $counts
    migrationEnabled = [bool]$hostInfo.VirtualMachineMigrationEnabled
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 6 -Compress
"""
    ),
}
