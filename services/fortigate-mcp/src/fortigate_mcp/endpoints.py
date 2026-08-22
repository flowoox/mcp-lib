from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ApiScope(StrEnum):
    GLOBAL = "global"
    VDOM = "vdom"


class FortiGateEndpoint(StrEnum):
    SYSTEM_STATUS = "system.status"
    HA_CONFIGURATION = "ha.configuration"
    INTERFACES = "interface.inventory"
    STATIC_ROUTES = "route.static"
    FIREWALL_POLICIES = "policy.inventory"
    IPSEC_PHASE1 = "vpn.ipsec.phase1"


@dataclass(frozen=True)
class EndpointSpec:
    endpoint: FortiGateEndpoint
    path: str
    scope: ApiScope
    collection: bool


ENDPOINTS: dict[FortiGateEndpoint, EndpointSpec] = {
    FortiGateEndpoint.SYSTEM_STATUS: EndpointSpec(
        endpoint=FortiGateEndpoint.SYSTEM_STATUS,
        path="/api/v2/monitor/system/status",
        scope=ApiScope.VDOM,
        collection=False,
    ),
    FortiGateEndpoint.HA_CONFIGURATION: EndpointSpec(
        endpoint=FortiGateEndpoint.HA_CONFIGURATION,
        path="/api/v2/cmdb/system/ha",
        scope=ApiScope.GLOBAL,
        collection=False,
    ),
    FortiGateEndpoint.INTERFACES: EndpointSpec(
        endpoint=FortiGateEndpoint.INTERFACES,
        path="/api/v2/cmdb/system/interface",
        scope=ApiScope.VDOM,
        collection=True,
    ),
    FortiGateEndpoint.STATIC_ROUTES: EndpointSpec(
        endpoint=FortiGateEndpoint.STATIC_ROUTES,
        path="/api/v2/cmdb/router/static",
        scope=ApiScope.VDOM,
        collection=True,
    ),
    FortiGateEndpoint.FIREWALL_POLICIES: EndpointSpec(
        endpoint=FortiGateEndpoint.FIREWALL_POLICIES,
        path="/api/v2/cmdb/firewall/policy",
        scope=ApiScope.VDOM,
        collection=True,
    ),
    FortiGateEndpoint.IPSEC_PHASE1: EndpointSpec(
        endpoint=FortiGateEndpoint.IPSEC_PHASE1,
        path="/api/v2/cmdb/vpn.ipsec/phase1-interface",
        scope=ApiScope.VDOM,
        collection=True,
    ),
}
