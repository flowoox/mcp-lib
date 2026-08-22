from __future__ import annotations

from enum import StrEnum


class ScriptId(StrEnum):
    DOMAIN_SUMMARY = "domain_summary"
    REPLICATION_HEALTH = "replication_health"
    LOCAL_SECURE_CHANNEL = "local_secure_channel"
    SECURITY_SNAPSHOT = "security_snapshot"
    GET_USER = "get_user"
    GET_COMPUTER = "get_computer"
    GET_GROUP = "get_group"


SCRIPTS: dict[ScriptId, str] = {
    ScriptId.DOMAIN_SUMMARY: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$forest = Get-ADForest -ErrorAction Stop
$dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
        hostName = $_.HostName
        ipv4Address = $_.IPv4Address
        site = $_.Site
        isGlobalCatalog = [bool]$_.IsGlobalCatalog
        operationMasterRoles = @($_.OperationMasterRoles | ForEach-Object { $_.ToString() })
        operatingSystem = $_.OperatingSystem
        operatingSystemVersion = $_.OperatingSystemVersion
    }
})
[pscustomobject]@{
    dnsRoot = $domain.DNSRoot
    netbiosName = $domain.NetBIOSName
    distinguishedName = $domain.DistinguishedName
    domainMode = $domain.DomainMode.ToString()
    forest = $forest.Name
    forestMode = $forest.ForestMode.ToString()
    pdcEmulator = $domain.PDCEmulator
    ridMaster = $domain.RIDMaster
    infrastructureMaster = $domain.InfrastructureMaster
    schemaMaster = $forest.SchemaMaster
    domainNamingMaster = $forest.DomainNamingMaster
    domainControllers = $dcs
} | ConvertTo-Json -Depth 8 -Compress
""",
    ScriptId.REPLICATION_HEALTH: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$failures = @(Get-ADReplicationFailure -Target * -Scope Forest -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
        server = $_.Server
        partner = $_.Partner
        failureCount = [int]$_.FailureCount
        firstFailureTime = $_.FirstFailureTime
        lastError = [int]$_.LastError
    }
})
$partners = @(Get-ADReplicationPartnerMetadata -Target * -Scope Forest -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
        server = $_.Server
        partner = $_.Partner
        partition = $_.Partition
        lastReplicationAttempt = $_.LastReplicationAttempt
        lastReplicationSuccess = $_.LastReplicationSuccess
        lastReplicationResult = [int]$_.LastReplicationResult
        consecutiveReplicationFailures = [int]$_.ConsecutiveReplicationFailures
    }
})
[pscustomobject]@{
    healthy = ($failures.Count -eq 0 -and @($partners | Where-Object { $_.LastReplicationResult -ne 0 }).Count -eq 0)
    failures = $failures
    partners = $partners
} | ConvertTo-Json -Depth 8 -Compress
""",
    ScriptId.LOCAL_SECURE_CHANNEL: r"""
$ErrorActionPreference = 'Stop'
$computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$role = [int]$computerSystem.DomainRole
$isDomainController = $role -ge 4
$secure = $null
$note = $null
if ($isDomainController) {
    $note = 'Test-ComputerSecureChannel is intended for domain members; use replication/domain-controller diagnostics for a DC.'
} else {
    $secure = [bool](Test-ComputerSecureChannel -ErrorAction Stop)
}
[pscustomobject]@{
    computerName = $env:COMPUTERNAME
    domain = $computerSystem.Domain
    domainRole = $role
    isDomainController = $isDomainController
    secureChannel = $secure
    note = $note
} | ConvertTo-Json -Depth 5 -Compress
""",
    ScriptId.SECURITY_SNAPSHOT: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$forest = Get-ADForest -ErrorAction Stop
$policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
$domainObject = Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
$recycle = Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -ErrorAction Stop
[pscustomobject]@{
    domainMode = $domain.DomainMode.ToString()
    forestMode = $forest.ForestMode.ToString()
    minimumPasswordLength = [int]$policy.MinPasswordLength
    passwordHistoryCount = [int]$policy.PasswordHistoryCount
    complexityEnabled = [bool]$policy.ComplexityEnabled
    reversibleEncryptionEnabled = [bool]$policy.ReversibleEncryptionEnabled
    lockoutThreshold = [int]$policy.LockoutThreshold
    minimumPasswordAgeDays = [double]$policy.MinPasswordAge.TotalDays
    maximumPasswordAgeDays = [double]$policy.MaxPasswordAge.TotalDays
    machineAccountQuota = [int]$domainObject.'ms-DS-MachineAccountQuota'
    recycleBinEnabled = (@($recycle.EnabledScopes).Count -gt 0)
} | ConvertTo-Json -Depth 5 -Compress
""",
    ScriptId.GET_USER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$user = Get-ADUser -Identity $p.identity -Properties DisplayName,Enabled,Mail,UserPrincipalName,SamAccountName,DistinguishedName,PasswordLastSet,LastLogonDate,LockedOut,PasswordNeverExpires,WhenCreated,WhenChanged -ErrorAction Stop
[pscustomobject]@{
    objectGuid = $user.ObjectGUID.ToString()
    samAccountName = $user.SamAccountName
    userPrincipalName = $user.UserPrincipalName
    displayName = $user.DisplayName
    distinguishedName = $user.DistinguishedName
    enabled = [bool]$user.Enabled
    lockedOut = [bool]$user.LockedOut
    mail = $user.Mail
    passwordLastSet = $user.PasswordLastSet
    passwordNeverExpires = [bool]$user.PasswordNeverExpires
    lastLogonDate = $user.LastLogonDate
    whenCreated = $user.WhenCreated
    whenChanged = $user.WhenChanged
} | ConvertTo-Json -Depth 5 -Compress
""",
    ScriptId.GET_COMPUTER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$computer = Get-ADComputer -Identity $p.identity -Properties DNSHostName,Enabled,OperatingSystem,OperatingSystemVersion,LastLogonDate,WhenCreated,WhenChanged -ErrorAction Stop
[pscustomobject]@{
    objectGuid = $computer.ObjectGUID.ToString()
    samAccountName = $computer.SamAccountName
    dnsHostName = $computer.DNSHostName
    distinguishedName = $computer.DistinguishedName
    enabled = [bool]$computer.Enabled
    operatingSystem = $computer.OperatingSystem
    operatingSystemVersion = $computer.OperatingSystemVersion
    lastLogonDate = $computer.LastLogonDate
    whenCreated = $computer.WhenCreated
    whenChanged = $computer.WhenChanged
} | ConvertTo-Json -Depth 5 -Compress
""",
    ScriptId.GET_GROUP: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$group = Get-ADGroup -Identity $p.identity -Properties Description,ManagedBy,WhenCreated,WhenChanged -ErrorAction Stop
[pscustomobject]@{
    objectGuid = $group.ObjectGUID.ToString()
    samAccountName = $group.SamAccountName
    name = $group.Name
    distinguishedName = $group.DistinguishedName
    groupCategory = $group.GroupCategory.ToString()
    groupScope = $group.GroupScope.ToString()
    description = $group.Description
    managedBy = $group.ManagedBy
    whenCreated = $group.WhenCreated
    whenChanged = $group.WhenChanged
} | ConvertTo-Json -Depth 5 -Compress
""",
}
