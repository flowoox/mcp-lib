from __future__ import annotations

from enum import StrEnum


class ScriptId(StrEnum):
    CLUSTER = "cluster"
    NODES = "nodes"
    GROUPS = "groups"
    GROUP_DETAIL = "group-detail"
    RESOURCES = "resources"
    NETWORKS = "networks"
    STORAGE = "storage"
    QUORUM = "quorum"
    EVENTS = "events"


_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$rawInput = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_INPUT')
if ([string]::IsNullOrWhiteSpace($rawInput)) { $inputData = [pscustomobject]@{} }
else { $inputData = $rawInput | ConvertFrom-Json }
Import-Module FailoverClusters -ErrorAction Stop
"""


def _script(body: str) -> str:
    return _PREAMBLE + "\n" + body.strip() + "\n"


SCRIPTS: dict[ScriptId, str] = {
    ScriptId.CLUSTER: _script(
        r"""
$cluster = Get-Cluster -ErrorAction Stop
$nodes = @(Get-ClusterNode -ErrorAction Stop)
$groups = @(Get-ClusterGroup -ErrorAction Stop)
$resources = @(Get-ClusterResource -ErrorAction Stop)
$csvs = @(Get-ClusterSharedVolume -ErrorAction SilentlyContinue)
$quorum = Get-ClusterQuorum -ErrorAction Stop
$nodeCounts = @{}
foreach ($group in @($nodes | Group-Object -Property State)) { $nodeCounts[[string]$group.Name] = [int]$group.Count }
$groupCounts = @{}
foreach ($group in @($groups | Group-Object -Property State)) { $groupCounts[[string]$group.Name] = [int]$group.Count }
$resourceCounts = @{}
foreach ($group in @($resources | Group-Object -Property State)) { $resourceCounts[[string]$group.Name] = [int]$group.Count }
$quorumResource = $null
try { if ($null -ne $quorum.QuorumResource) { $quorumResource = [string]$quorum.QuorumResource.Name } } catch {}
$dynamicQuorum = $null
try { if ($null -ne $cluster.DynamicQuorum) { $dynamicQuorum = [int]$cluster.DynamicQuorum } } catch {}
[ordered]@{
  items = @([ordered]@{
    clusterName = [string]$cluster.Name
    available = $true
    nodeCounts = $nodeCounts
    groupCounts = $groupCounts
    resourceCounts = $resourceCounts
    sharedVolumeCount = [int]$csvs.Count
    quorumType = [string]$quorum.QuorumType
    quorumResource = $quorumResource
    dynamicQuorum = $dynamicQuorum
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 7 -Compress
"""
    ),
    ScriptId.NODES: _script(
        r"""
$limit = [math]::Min(500, [math]::Max(1, [int]$inputData.limit))
$offset = [math]::Min(10000, [math]::Max(0, [int]$inputData.offset))
$all = @(Get-ClusterNode -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $nodeWeight = $null; $dynamicWeight = $null; $drainStatus = $null
  try { $nodeWeight = [int]$_.NodeWeight } catch {}
  try { $dynamicWeight = [int]$_.DynamicWeight } catch {}
  try { if ($null -ne $_.DrainStatus) { $drainStatus = [string]$_.DrainStatus } } catch {}
  [ordered]@{
    name = [string]$_.Name
    state = [string]$_.State
    nodeWeight = $nodeWeight
    dynamicWeight = $dynamicWeight
    drainStatus = $drainStatus
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.GROUPS: _script(
        r"""
$limit = [math]::Min(500, [math]::Max(1, [int]$inputData.limit))
$offset = [math]::Min(10000, [math]::Max(0, [int]$inputData.offset))
$all = @(Get-ClusterGroup -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $failoverPeriod = $null; $failoverThreshold = $null
  try { $failoverPeriod = [int]$_.FailoverPeriod } catch {}
  try { $failoverThreshold = [int]$_.FailoverThreshold } catch {}
  [ordered]@{
    name = [string]$_.Name
    state = [string]$_.State
    ownerNode = if ($null -eq $_.OwnerNode) { $null } else { [string]$_.OwnerNode.Name }
    isCoreGroup = [bool]$_.IsCoreGroup
    failoverPeriodHours = $failoverPeriod
    failoverThreshold = $failoverThreshold
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.GROUP_DETAIL: _script(
        r"""
$groupName = [string]$inputData.groupName
$resourceLimit = [math]::Min(256, [math]::Max(1, [int]$inputData.resourceLimit))
$group = Get-ClusterGroup -Name $groupName -ErrorAction Stop
$allResources = @(Get-ClusterResource -ErrorAction Stop | Where-Object { $_.OwnerGroup.Name -eq $group.Name } | Sort-Object -Property Name)
$resourcePage = @($allResources | Select-Object -First $resourceLimit)
$resources = @($resourcePage | ForEach-Object {
  $persistentState = $null; $restartAction = $null
  try { $persistentState = [int]$_.PersistentState } catch {}
  try { $restartAction = [int]$_.RestartAction } catch {}
  [ordered]@{
    name = [string]$_.Name
    resourceType = [string]$_.ResourceType
    state = [string]$_.State
    ownerGroup = if ($null -eq $_.OwnerGroup) { $null } else { [string]$_.OwnerGroup.Name }
    ownerNode = if ($null -eq $_.OwnerNode) { $null } else { [string]$_.OwnerNode.Name }
    isCoreResource = [bool]$_.IsCoreResource
    persistentState = $persistentState
    restartAction = $restartAction
  }
})
$failoverPeriod = $null; $failoverThreshold = $null
try { $failoverPeriod = [int]$group.FailoverPeriod } catch {}
try { $failoverThreshold = [int]$group.FailoverThreshold } catch {}
[ordered]@{
  items = @([ordered]@{
    name = [string]$group.Name
    state = [string]$group.State
    ownerNode = if ($null -eq $group.OwnerNode) { $null } else { [string]$group.OwnerNode.Name }
    isCoreGroup = [bool]$group.IsCoreGroup
    failoverPeriodHours = $failoverPeriod
    failoverThreshold = $failoverThreshold
    resources = $resources
    resourceCount = [int]$allResources.Count
    resourcesTruncated = [bool]($allResources.Count -gt $resources.Count)
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 8 -Compress
"""
    ),
    ScriptId.RESOURCES: _script(
        r"""
$limit = [math]::Min(500, [math]::Max(1, [int]$inputData.limit))
$offset = [math]::Min(10000, [math]::Max(0, [int]$inputData.offset))
$groupName = [string]$inputData.groupName
$all = @(Get-ClusterResource -ErrorAction Stop)
if (-not [string]::IsNullOrWhiteSpace($groupName)) {
  $all = @($all | Where-Object { $_.OwnerGroup.Name -eq $groupName })
}
$all = @($all | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $persistentState = $null; $restartAction = $null
  try { $persistentState = [int]$_.PersistentState } catch {}
  try { $restartAction = [int]$_.RestartAction } catch {}
  [ordered]@{
    name = [string]$_.Name
    resourceType = [string]$_.ResourceType
    state = [string]$_.State
    ownerGroup = if ($null -eq $_.OwnerGroup) { $null } else { [string]$_.OwnerGroup.Name }
    ownerNode = if ($null -eq $_.OwnerNode) { $null } else { [string]$_.OwnerNode.Name }
    isCoreResource = [bool]$_.IsCoreResource
    persistentState = $persistentState
    restartAction = $restartAction
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.NETWORKS: _script(
        r"""
$limit = [math]::Min(500, [math]::Max(1, [int]$inputData.limit))
$offset = [math]::Min(10000, [math]::Max(0, [int]$inputData.offset))
$all = @(Get-ClusterNetwork -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $metric = $null; $autoMetric = $null
  try { $metric = [int]$_.Metric } catch {}
  try { $autoMetric = [bool]$_.AutoMetric } catch {}
  [ordered]@{
    name = [string]$_.Name
    state = [string]$_.State
    role = [string]$_.Role
    address = [string]$_.Address
    addressMask = [string]$_.AddressMask
    metric = $metric
    autoMetric = $autoMetric
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.STORAGE: _script(
        r"""
$limit = [math]::Min(500, [math]::Max(1, [int]$inputData.limit))
$offset = [math]::Min(10000, [math]::Max(0, [int]$inputData.offset))
$all = @(Get-ClusterSharedVolume -ErrorAction Stop | Sort-Object -Property Name)
$page = @($all | Select-Object -Skip $offset -First $limit)
$items = @($page | ForEach-Object {
  $volumePath = $null; $totalBytes = $null; $freeBytes = $null; $percentFree = $null
  try {
    $info = @($_.SharedVolumeInfo | Select-Object -First 1)
    if ($info.Count -gt 0) {
      $volumePath = [string]$info[0].FriendlyVolumeName
      $partition = $info[0].Partition
      if ($null -ne $partition) {
        $totalBytes = [int64]$partition.Size
        $freeBytes = [int64]$partition.FreeSpace
        if ($totalBytes -gt 0) { $percentFree = [math]::Round(($freeBytes * 100.0) / $totalBytes, 2) }
      }
    }
  } catch {}
  [ordered]@{
    name = [string]$_.Name
    state = [string]$_.State
    ownerNode = if ($null -eq $_.OwnerNode) { $null } else { [string]$_.OwnerNode.Name }
    volumePath = $volumePath
    totalBytes = $totalBytes
    freeBytes = $freeBytes
    percentFree = $percentFree
  }
})
$next = if (($offset + $items.Count) -lt $all.Count) { [string]($offset + $items.Count) } else { $null }
[ordered]@{ items = $items; nextCursor = $next } | ConvertTo-Json -Depth 7 -Compress
"""
    ),
    ScriptId.QUORUM: _script(
        r"""
$cluster = Get-Cluster -ErrorAction Stop
$quorum = Get-ClusterQuorum -ErrorAction Stop
$resourceName = $null; $witnessType = $null
try {
  if ($null -ne $quorum.QuorumResource) {
    $resourceName = [string]$quorum.QuorumResource.Name
    $witnessType = [string]$quorum.QuorumResource.ResourceType
  }
} catch {}
[ordered]@{
  items = @([ordered]@{
    clusterName = [string]$cluster.Name
    quorumType = [string]$quorum.QuorumType
    quorumResource = $resourceName
    witnessType = $witnessType
  })
  nextCursor = $null
} | ConvertTo-Json -Depth 6 -Compress
"""
    ),
    ScriptId.EVENTS: _script(
        r"""
$limit = [math]::Min(200, [math]::Max(1, [int]$inputData.limit))
$lookback = [int]$inputData.lookbackMinutes
$level = [string]$inputData.level
$includeMessage = [bool]$inputData.includeMessage
$logName = 'Microsoft-Windows-FailoverClustering/Operational'
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
