from __future__ import annotations

from enum import StrEnum


class ProvisioningScriptId(StrEnum):
    PREFLIGHT_CREATE_DISABLED_USER = "preflight_create_disabled_user"
    CREATE_DISABLED_USER = "create_disabled_user"


PROVISIONING_SCRIPTS: dict[ProvisioningScriptId, str] = {
    ProvisioningScriptId.PREFLIGHT_CREATE_DISABLED_USER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$sam = [string]$p.samAccountName
$upn = [string]$p.userPrincipalName
$ou = Get-ADOrganizationalUnit -Identity ([string]$p.ouDn) -Properties DistinguishedName -ErrorAction Stop
$properties = @('DisplayName','GivenName','Surname','Mail','EmployeeID','Description','Enabled','UserPrincipalName','SamAccountName')
$samMatches = @(Get-ADUser -Filter { SamAccountName -eq $sam } -Properties $properties -ErrorAction Stop)
$upnMatches = @(Get-ADUser -Filter { UserPrincipalName -eq $upn } -Properties $properties -ErrorAction Stop)
function Convert-User([object]$user) {
    if ($null -eq $user) { return $null }
    return [pscustomobject]@{
        objectGuid = $user.ObjectGUID.ToString()
        name = $user.Name
        samAccountName = $user.SamAccountName
        userPrincipalName = $user.UserPrincipalName
        displayName = $user.DisplayName
        givenName = $user.GivenName
        surname = $user.Surname
        mail = $user.Mail
        employeeId = $user.EmployeeID
        description = $user.Description
        distinguishedName = $user.DistinguishedName
        enabled = [bool]$user.Enabled
    }
}
[pscustomobject]@{
    ouDistinguishedName = $ou.DistinguishedName
    samMatches = @($samMatches | ForEach-Object { Convert-User $_ })
    upnMatches = @($upnMatches | ForEach-Object { Convert-User $_ })
} | ConvertTo-Json -Depth 7 -Compress
""",
    ProvisioningScriptId.CREATE_DISABLED_USER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$sam = [string]$p.samAccountName
$upn = [string]$p.userPrincipalName
$ou = Get-ADOrganizationalUnit -Identity ([string]$p.ouDn) -Properties DistinguishedName -ErrorAction Stop
$properties = @('DisplayName','GivenName','Surname','Mail','EmployeeID','Description','Enabled','UserPrincipalName','SamAccountName')
$samMatches = @(Get-ADUser -Filter { SamAccountName -eq $sam } -Properties $properties -ErrorAction Stop)
$upnMatches = @(Get-ADUser -Filter { UserPrincipalName -eq $upn } -Properties $properties -ErrorAction Stop)
if ($samMatches.Count -gt 1) {
    throw 'Multiple users matched the requested sAMAccountName; refusing provisioning.'
}
$existing = if ($samMatches.Count -eq 1) { $samMatches[0] } else { $null }
$upnConflict = @($upnMatches | Where-Object {
    $null -eq $existing -or $_.ObjectGUID -ne $existing.ObjectGUID
})
if ($upnConflict.Count -gt 0) {
    throw 'The requested userPrincipalName is already assigned to another user.'
}
function Test-OptionalMatch([object]$requested, [object]$actual) {
    if ($null -eq $requested -or [string]::IsNullOrWhiteSpace([string]$requested)) { return $true }
    return [string]::Equals([string]$requested, [string]$actual, [System.StringComparison]::OrdinalIgnoreCase)
}
if ($null -ne $existing) {
    $inOu = $existing.DistinguishedName.EndsWith(',' + $ou.DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)
    $matches = (
        [string]::Equals($existing.Name, [string]$p.name, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals($existing.SamAccountName, $sam, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals($existing.UserPrincipalName, $upn, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals($existing.DisplayName, [string]$p.displayName, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-OptionalMatch $p.givenName $existing.GivenName) -and
        (Test-OptionalMatch $p.surname $existing.Surname) -and
        (Test-OptionalMatch $p.mail $existing.Mail) -and
        (Test-OptionalMatch $p.employeeId $existing.EmployeeID) -and
        (Test-OptionalMatch $p.description $existing.Description) -and
        $inOu -and
        -not [bool]$existing.Enabled
    )
    if (-not $matches) {
        throw 'An existing user matches the requested sAMAccountName but does not match the approved provisioning intent.'
    }
    [pscustomobject]@{
        objectGuid = $existing.ObjectGUID.ToString()
        distinguishedName = $existing.DistinguishedName
        changed = $false
        createdDisabled = $false
    } | ConvertTo-Json -Depth 5 -Compress
    exit 0
}
$params = @{
    Name = [string]$p.name
    SamAccountName = $sam
    UserPrincipalName = $upn
    DisplayName = [string]$p.displayName
    Path = $ou.DistinguishedName
    Enabled = $false
}
if (-not [string]::IsNullOrWhiteSpace([string]$p.givenName)) { $params['GivenName'] = [string]$p.givenName }
if (-not [string]::IsNullOrWhiteSpace([string]$p.surname)) { $params['Surname'] = [string]$p.surname }
if (-not [string]::IsNullOrWhiteSpace([string]$p.mail)) { $params['EmailAddress'] = [string]$p.mail }
if (-not [string]::IsNullOrWhiteSpace([string]$p.employeeId)) { $params['EmployeeID'] = [string]$p.employeeId }
if (-not [string]::IsNullOrWhiteSpace([string]$p.description)) { $params['Description'] = [string]$p.description }
$created = New-ADUser @params -PassThru -Confirm:$false -ErrorAction Stop
$readback = Get-ADUser -Identity $created.ObjectGUID -Properties $properties -ErrorAction Stop
[pscustomobject]@{
    objectGuid = $readback.ObjectGUID.ToString()
    distinguishedName = $readback.DistinguishedName
    changed = $true
    createdDisabled = (-not [bool]$readback.Enabled)
} | ConvertTo-Json -Depth 5 -Compress
""",
}
