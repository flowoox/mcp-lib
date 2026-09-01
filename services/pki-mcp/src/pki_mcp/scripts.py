from __future__ import annotations

from enum import StrEnum


class ScriptId(StrEnum):
    CA = "ca"
    EXPIRING = "expiring"
    REVOCATION_PUBLICATION = "revocation-publication"
    EVENTS = "events"


_PREAMBLE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$payloadJson = [Environment]::GetEnvironmentVariable('FLOWOOX_MCP_INPUT')
if ([string]::IsNullOrWhiteSpace($payloadJson)) { throw 'Missing bounded PKI payload' }
$payload = $payloadJson | ConvertFrom-Json -Depth 8
if ([string]::IsNullOrWhiteSpace([string]$payload.caConfig)) { throw 'Missing CA configuration' }

function Get-CaName {
  param([string]$Config)
  $parts = $Config -split '\\', 2
  if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[1])) { throw 'Invalid CA configuration' }
  return $parts[1]
}

function Get-CaRegistryConfig {
  param([string]$CaName)
  $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
  return Get-ItemProperty -LiteralPath $path -ErrorAction Stop
}

function Get-CaCertificate {
  param([object]$Config)
  $hashes = @($Config.CACertHash)
  $thumbprint = $null
  foreach ($hash in $hashes) {
    if ($null -eq $hash) { continue }
    $candidate = ([string]$hash -replace '\s', '').Trim()
    if ($candidate -match '^[0-9A-Fa-f]{40,128}$') {
      $thumbprint = $candidate
      break
    }
  }
  if ([string]::IsNullOrWhiteSpace($thumbprint)) { throw 'CA certificate hash is unavailable' }
  return Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop
}

function Write-BoundedJson {
  param([object[]]$Items, [string]$NextCursor = $null)
  $result = [ordered]@{ items = @($Items); nextCursor = $NextCursor }
  [Console]::Out.Write(($result | ConvertTo-Json -Depth 8 -Compress))
}
""".strip()


_CA = _PREAMBLE + r"""
$caName = Get-CaName -Config ([string]$payload.caConfig)
$config = Get-CaRegistryConfig -CaName $caName
$cert = Get-CaCertificate -Config $config
$service = Get-Service -Name 'CertSvc' -ErrorAction Stop
$now = [DateTime]::UtcNow
$notAfter = $cert.NotAfter.ToUniversalTime()
$item = [ordered]@{
  serviceState = [string]$service.Status
  certificateNotBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
  certificateNotAfter = $notAfter.ToString('o')
  certificateDaysRemaining = [int][Math]::Floor(($notAfter - $now).TotalDays)
  signatureAlgorithm = [string]$cert.SignatureAlgorithm.FriendlyName
  crlPeriod = if ($null -eq $config.CRLPeriod) { $null } else { [int]$config.CRLPeriod }
  crlPeriodUnits = if ($null -eq $config.CRLPeriodUnits) { $null } else { [string]$config.CRLPeriodUnits }
  crlOverlapPeriod = if ($null -eq $config.CRLOverlapPeriod) { $null } else { [int]$config.CRLOverlapPeriod }
  crlOverlapUnits = if ($null -eq $config.CRLOverlapUnits) { $null } else { [string]$config.CRLOverlapUnits }
}
Write-BoundedJson -Items @($item)
"""


_REVOCATION_PUBLICATION = _PREAMBLE + r"""
$caName = Get-CaName -Config ([string]$payload.caConfig)
$config = Get-CaRegistryConfig -CaName $caName
$cert = Get-CaCertificate -Config $config
$crlTargets = @($config.CRLPublicationURLs | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
$caTargets = @($config.CACertPublicationURLs | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
$cdpPresent = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.31' }).Count -gt 0
$aiaPresent = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }).Count -gt 0
$item = [ordered]@{
  crlPublicationTargetCount = [int]$crlTargets.Count
  caCertificatePublicationTargetCount = [int]$caTargets.Count
  caCertificateCdpExtensionPresent = [bool]$cdpPresent
  caCertificateAiaExtensionPresent = [bool]$aiaPresent
}
Write-BoundedJson -Items @($item)
"""


_EXPIRING = _PREAMBLE + r"""
$limit = [int]$payload.limit
$days = [int]$payload.expiryDays
if ($limit -lt 1 -or $limit -gt 250) { throw 'Invalid result limit' }
if ($days -lt 1 -or $days -gt 730) { throw 'Invalid expiry window' }

$view = New-Object -ComObject 'CertificateAuthority.View'
[void]$view.OpenConnection([string]$payload.caConfig)

$columnNames = @('RequestID', 'Certificate Template', 'NotBefore', 'NotAfter', 'Revocation Date')
$view.SetResultColumnCount($columnNames.Count)
foreach ($name in $columnNames) {
  $index = $view.GetColumnIndex($false, $name)
  $view.SetResultColumn($index)
}

$notAfterIndex = $view.GetColumnIndex($false, 'NotAfter')
$now = [DateTime]::UtcNow
$cutoff = $now.AddDays($days)
# CVR_SEEK_GE = 0x8, CVR_SEEK_LE = 0x4, CVR_SORT_NONE = 0
$view.SetRestriction($notAfterIndex, 0x8, 0, $now)
$view.SetRestriction($notAfterIndex, 0x4, 0, $cutoff)

$rows = $view.OpenView()
$items = New-Object System.Collections.Generic.List[object]
$hasMore = $false
$scanned = 0
$scanLimit = [Math]::Min([Math]::Max($limit * 4, $limit), 500)
while ($rows.Next() -ne -1) {
  $scanned++
  if ($items.Count -ge $limit -or $scanned -gt $scanLimit) {
    $hasMore = $true
    break
  }
  $columns = $rows.EnumCertViewColumn()
  $values = New-Object System.Collections.Generic.List[object]
  if ($columns.Next() -ne -1) {
    do {
      $values.Add($columns.GetValue(1))
    } until ($columns.Next() -eq -1)
  }
  if ($values.Count -ne 5) { throw 'Unexpected Certificate Services view shape' }
  $revocationDate = $values[4]
  $isRevoked = $null -ne $revocationDate -and -not [string]::IsNullOrWhiteSpace([string]$revocationDate)
  if ($isRevoked) { continue }
  $notBefore = ([DateTime]$values[2]).ToUniversalTime()
  $notAfter = ([DateTime]$values[3]).ToUniversalTime()
  $template = [string]$values[1]
  if ([string]::IsNullOrWhiteSpace($template)) { $template = 'unknown' }
  $items.Add([ordered]@{
    requestId = [int]$values[0]
    template = $template
    notBefore = $notBefore.ToString('o')
    notAfter = $notAfter.ToString('o')
    daysRemaining = [int][Math]::Floor(($notAfter - $now).TotalDays)
  })
}
# ICertView exposes no continuation token contract. The MCP deliberately returns a bounded
# first page only; hasMore is represented as truncation without permitting automatic crawl.
$next = if ($hasMore) { 'truncated' } else { $null }
Write-BoundedJson -Items @($items) -NextCursor $next
"""


_EVENTS = _PREAMBLE + r"""
$limit = [int]$payload.limit
$lookback = [int]$payload.lookbackMinutes
$level = [string]$payload.level
if ($limit -lt 1 -or $limit -gt 250) { throw 'Invalid result limit' }
if ($lookback -lt 1 -or $lookback -gt 10080) { throw 'Invalid event lookback' }
if ($level -notin @('all','critical','error','warning')) { throw 'Invalid event level' }

$levels = switch ($level) {
  'critical' { @(1) }
  'error' { @(1,2) }
  'warning' { @(1,2,3) }
  default { @(1,2,3,4) }
}
$start = [DateTime]::UtcNow.AddMinutes(-1 * $lookback)
$events = @(Get-WinEvent -FilterHashtable @{
  LogName='Application'
  ProviderName='Microsoft-Windows-CertificationAuthority'
  StartTime=$start
  Level=$levels
} -MaxEvents $limit -ErrorAction SilentlyContinue)
$items = foreach ($event in $events) {
  [ordered]@{
    eventId = [int]$event.Id
    level = [string]$event.LevelDisplayName
    provider = [string]$event.ProviderName
    timeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
  }
}
Write-BoundedJson -Items @($items)
"""


SCRIPTS: dict[ScriptId, str] = {
    ScriptId.CA: _CA,
    ScriptId.EXPIRING: _EXPIRING,
    ScriptId.REVOCATION_PUBLICATION: _REVOCATION_PUBLICATION,
    ScriptId.EVENTS: _EVENTS,
}
