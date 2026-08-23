from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EntraEndpoint(StrEnum):
    ORGANIZATIONS = "organization.inventory"
    USERS = "user.inventory"
    GROUPS = "group.inventory"
    DEVICES = "device.inventory"
    APPLICATIONS = "application.inventory"
    SERVICE_PRINCIPALS = "service-principal.inventory"
    DIRECTORY_ROLES = "directory-role.inventory"
    CONDITIONAL_ACCESS = "conditional-access.policy.inventory"


@dataclass(frozen=True)
class EndpointSpec:
    endpoint: EntraEndpoint
    path: str
    collection: bool
    select_fields: tuple[str, ...]
    application_permission: str


ENDPOINTS: dict[EntraEndpoint, EndpointSpec] = {
    EntraEndpoint.ORGANIZATIONS: EndpointSpec(
        EntraEndpoint.ORGANIZATIONS,
        "/v1.0/organization",
        True,
        ("id", "displayName", "verifiedDomains", "onPremisesSyncEnabled", "technicalNotificationMails"),
        "Organization.Read.All",
    ),
    EntraEndpoint.USERS: EndpointSpec(
        EntraEndpoint.USERS,
        "/v1.0/users",
        True,
        ("id", "displayName", "userPrincipalName", "accountEnabled", "userType", "mail", "createdDateTime"),
        "User.Read.All",
    ),
    EntraEndpoint.GROUPS: EndpointSpec(
        EntraEndpoint.GROUPS,
        "/v1.0/groups",
        True,
        ("id", "displayName", "description", "mail", "mailEnabled", "securityEnabled", "groupTypes"),
        "Group.Read.All",
    ),
    EntraEndpoint.DEVICES: EndpointSpec(
        EntraEndpoint.DEVICES,
        "/v1.0/devices",
        True,
        ("id", "displayName", "deviceId", "accountEnabled", "operatingSystem", "operatingSystemVersion", "trustType", "approximateLastSignInDateTime"),
        "Device.Read.All",
    ),
    EntraEndpoint.APPLICATIONS: EndpointSpec(
        EntraEndpoint.APPLICATIONS,
        "/v1.0/applications",
        True,
        ("id", "appId", "displayName", "signInAudience", "publisherDomain", "createdDateTime"),
        "Application.Read.All",
    ),
    EntraEndpoint.SERVICE_PRINCIPALS: EndpointSpec(
        EntraEndpoint.SERVICE_PRINCIPALS,
        "/v1.0/servicePrincipals",
        True,
        ("id", "appId", "displayName", "accountEnabled", "servicePrincipalType", "signInAudience", "appOwnerOrganizationId"),
        "Application.Read.All",
    ),
    EntraEndpoint.DIRECTORY_ROLES: EndpointSpec(
        EntraEndpoint.DIRECTORY_ROLES,
        "/v1.0/directoryRoles",
        True,
        ("id", "displayName", "description", "roleTemplateId"),
        "RoleManagement.Read.Directory",
    ),
    EntraEndpoint.CONDITIONAL_ACCESS: EndpointSpec(
        EntraEndpoint.CONDITIONAL_ACCESS,
        "/v1.0/identity/conditionalAccess/policies",
        True,
        ("id", "displayName", "state", "createdDateTime", "modifiedDateTime", "conditions", "grantControls", "sessionControls"),
        "Policy.Read.All",
    ),
}
