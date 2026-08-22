from __future__ import annotations

from enum import StrEnum


class ProvisioningScriptId(StrEnum):
    PREFLIGHT_CREATE_DISABLED_USER = "preflight_create_disabled_user"
    CREATE_DISABLED_USER = "create_disabled_user"
    PREFLIGHT_CREDENTIAL_BOOTSTRAP = "preflight_credential_bootstrap"
    SET_INITIAL_PASSWORD = "set_initial_password"


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
    $requestedText = if ($null -eq $requested) { '' } else { [string]$requested }
    $actualText = if ($null -eq $actual) { '' } else { [string]$actual }
    return [string]::Equals($requestedText, $actualText, [System.StringComparison]::OrdinalIgnoreCase)
}
function Get-ParentDistinguishedName([string]$distinguishedName) {
    $escaped = $false
    for ($index = 0; $index -lt $distinguishedName.Length; $index++) {
        $character = $distinguishedName[$index]
        if ($escaped) {
            $escaped = $false
            continue
        }
        if ($character -eq [char]92) {
            $escaped = $true
            continue
        }
        if ($character -eq ',') {
            return $distinguishedName.Substring($index + 1)
        }
    }
    return ''
}
if ($null -ne $existing) {
    $parentDn = Get-ParentDistinguishedName $existing.DistinguishedName
    $inOu = [string]::Equals($parentDn, $ou.DistinguishedName, [System.StringComparison]::OrdinalIgnoreCase)
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
    ProvisioningScriptId.PREFLIGHT_CREDENTIAL_BOOTSTRAP: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$user = Get-ADUser -Identity ([string]$p.identity) -Properties Enabled,PasswordLastSet,SamAccountName,UserPrincipalName,DistinguishedName -ErrorAction Stop
$passwordLastSet = if ($null -eq $user.PasswordLastSet) { $null } else { $user.PasswordLastSet.ToUniversalTime().ToString('o') }
[pscustomobject]@{
    objectGuid = $user.ObjectGUID.ToString()
    samAccountName = $user.SamAccountName
    userPrincipalName = $user.UserPrincipalName
    distinguishedName = $user.DistinguishedName
    enabled = [bool]$user.Enabled
    credentialEstablished = ($null -ne $user.PasswordLastSet)
    passwordLastSet = $passwordLastSet
} | ConvertTo-Json -Depth 5 -Compress
""",
    ProvisioningScriptId.SET_INITIAL_PASSWORD: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$user = Get-ADUser -Identity ([string]$p.identity) -Properties Enabled,PasswordLastSet -ErrorAction Stop
$expectedGuid = [guid]([string]$p.expectedObjectGuid)
if ($user.ObjectGUID -ne $expectedGuid) {
    throw 'The AD user object GUID no longer matches the approved identity.'
}
if ([bool]$user.Enabled) {
    throw 'Credential bootstrap is allowed only while the AD user remains disabled.'
}
if ($null -ne $user.PasswordLastSet) {
    throw 'The AD user already has password state; refusing an implicit password reset.'
}
$secret = [Console]::In.ReadToEnd()
if ([string]::IsNullOrEmpty($secret)) {
    throw 'The credential secret stream was empty.'
}
if ($secret.IndexOf([char]0) -ge 0) {
    throw 'The credential secret stream contained an invalid character.'
}
$secure = $null
try {
    $secure = ConvertTo-SecureString -String $secret -AsPlainText -Force
    Set-ADAccountPassword -Identity $user.ObjectGUID -Reset -NewPassword $secure -Confirm:$false -ErrorAction Stop
}
finally {
    $secret = $null
    $secure = $null
}
$readback = Get-ADUser -Identity $user.ObjectGUID -Properties Enabled,PasswordLastSet -ErrorAction Stop
$passwordLastSet = if ($null -eq $readback.PasswordLastSet) { $null } else { $readback.PasswordLastSet.ToUniversalTime().ToString('o') }
if ($null -eq $readback.PasswordLastSet) {
    throw 'AD did not report password state after credential bootstrap.'
}
if ([bool]$readback.Enabled) {
    throw 'AD user became enabled during credential bootstrap; refusing success.'
}
[pscustomobject]@{
    objectGuid = $readback.ObjectGUID.ToString()
    enabled = [bool]$readback.Enabled
    credentialEstablished = ($null -ne $readback.PasswordLastSet)
    passwordLastSet = $passwordLastSet
    changed = $true
} | ConvertTo-Json -Depth 5 -Compress
""",
}
