from __future__ import annotations

from enum import StrEnum


class WriteScriptId(StrEnum):
    WRITE_CONTEXT = "write_context"
    USER_PRESTATE = "user_prestate"
    PATH_PRESTATE = "path_prestate"
    CREATE_DISABLED_USER = "create_disabled_user"
    REMOVE_CREATED_USER = "remove_created_user"
    MEMBERSHIP_PRESTATE = "membership_prestate"
    ADD_GROUP_MEMBER = "add_group_member"
    REMOVE_GROUP_MEMBER = "remove_group_member"


MUTATING_WRITE_SCRIPT_IDS = frozenset(
    {
        WriteScriptId.CREATE_DISABLED_USER,
        WriteScriptId.REMOVE_CREATED_USER,
        WriteScriptId.ADD_GROUP_MEMBER,
        WriteScriptId.REMOVE_GROUP_MEMBER,
    }
)


WRITE_SCRIPTS: dict[WriteScriptId, str] = {
    WriteScriptId.WRITE_CONTEXT: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
[pscustomobject]@{
    server = $domain.PDCEmulator
    dnsRoot = $domain.DNSRoot
} | ConvertTo-Json -Depth 4 -Compress
""",
    WriteScriptId.USER_PRESTATE: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
try {
    $user = Get-ADUser -Identity $p.identity -Server $p.server -Properties Enabled,UserPrincipalName,DistinguishedName -ErrorAction Stop
    [pscustomobject]@{
        exists = $true
        objectGuid = $user.ObjectGUID.ToString()
        samAccountName = $user.SamAccountName
        userPrincipalName = $user.UserPrincipalName
        distinguishedName = $user.DistinguishedName
        enabled = [bool]$user.Enabled
    } | ConvertTo-Json -Depth 5 -Compress
} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    [pscustomobject]@{ exists = $false } | ConvertTo-Json -Depth 3 -Compress
}
""",
    WriteScriptId.PATH_PRESTATE: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$target = Get-ADObject -Identity $p.path -Server $p.server -Properties ObjectClass -ErrorAction Stop
[pscustomobject]@{
    exists = $true
    objectGuid = $target.ObjectGUID.ToString()
    distinguishedName = $target.DistinguishedName
    objectClass = $target.ObjectClass
} | ConvertTo-Json -Depth 4 -Compress
""",
    WriteScriptId.CREATE_DISABLED_USER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$newUserParams = @{
    Name = $p.display_name
    SamAccountName = $p.sam_account_name
    UserPrincipalName = $p.user_principal_name
    DisplayName = $p.display_name
    GivenName = $p.given_name
    Surname = $p.surname
    Path = $p.path
    Enabled = $false
    Server = $p.server
    ErrorAction = 'Stop'
}
if ($null -ne $p.mail -and $p.mail -ne '') {
    $newUserParams['EmailAddress'] = $p.mail
}
New-ADUser @newUserParams
$user = Get-ADUser -Identity $p.sam_account_name -Server $p.server -Properties Enabled,UserPrincipalName,DistinguishedName,Mail -ErrorAction Stop
[pscustomobject]@{
    objectGuid = $user.ObjectGUID.ToString()
    samAccountName = $user.SamAccountName
    userPrincipalName = $user.UserPrincipalName
    distinguishedName = $user.DistinguishedName
    enabled = [bool]$user.Enabled
    mail = $user.Mail
} | ConvertTo-Json -Depth 5 -Compress
""",
    WriteScriptId.REMOVE_CREATED_USER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
Remove-ADUser -Identity $p.object_guid -Server $p.server -Confirm:$false -ErrorAction Stop
[pscustomobject]@{
    removed = $true
    objectGuid = $p.object_guid
} | ConvertTo-Json -Depth 3 -Compress
""",
    WriteScriptId.MEMBERSHIP_PRESTATE: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
$user = Get-ADUser -Identity $p.user_identity -Server $p.server -ErrorAction Stop
$group = Get-ADGroup -Identity $p.group_identity -Server $p.server -ErrorAction Stop
$directGroups = @(Get-ADPrincipalGroupMembership -Identity $user -Server $p.server -ErrorAction Stop)
$isMember = (@($directGroups | Where-Object { $_.ObjectGUID -eq $group.ObjectGUID }).Count -gt 0)
[pscustomobject]@{
    userGuid = $user.ObjectGUID.ToString()
    userDistinguishedName = $user.DistinguishedName
    groupGuid = $group.ObjectGUID.ToString()
    groupDistinguishedName = $group.DistinguishedName
    isMember = $isMember
} | ConvertTo-Json -Depth 5 -Compress
""",
    WriteScriptId.ADD_GROUP_MEMBER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
Add-ADGroupMember -Identity $p.group_guid -Members $p.user_guid -Server $p.server -ErrorAction Stop
[pscustomobject]@{
    changed = $true
    userGuid = $p.user_guid
    groupGuid = $p.group_guid
} | ConvertTo-Json -Depth 3 -Compress
""",
    WriteScriptId.REMOVE_GROUP_MEMBER: r"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$p = $env:FLOWOOX_MCP_INPUT | ConvertFrom-Json -ErrorAction Stop
Remove-ADGroupMember -Identity $p.group_guid -Members $p.user_guid -Server $p.server -Confirm:$false -ErrorAction Stop
[pscustomobject]@{
    changed = $true
    userGuid = $p.user_guid
    groupGuid = $p.group_guid
} | ConvertTo-Json -Depth 3 -Compress
""",
}
