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
    FIREWALL_ADDRESSES = "address.inventory"
    IPSEC_PHASE1 = "vpn.ipsec.phase1"


@dataclass(frozen=True)
class EndpointSpec:
    endpoint: FortiGateEndpoint
    path: str
    scope: ApiScope
    collection: bool
    format_fields: tuple[str, ...] = ()


ENDPOINTS: dict[FortiGateEndpoint, EndpointSpec] = {
    FortiGateEndpoint.SYSTEM_STATUS: EndpointSpec(
        FortiGateEndpoint.SYSTEM_STATUS,
        "/api/v2/monitor/system/status",
        ApiScope.VDOM,
        False,
    ),
    FortiGateEndpoint.HA_CONFIGURATION: EndpointSpec(
        FortiGateEndpoint.HA_CONFIGURATION,
        "/api/v2/cmdb/system/ha",
        ApiScope.GLOBAL,
        False,
        (
            "mode", "group-name", "group-id", "priority", "override", "session-pickup",
            "hbdev", "monitor", "unicast-hb", "unicast-hb-peerip", "ha-mgmt-status",
            "ha-mgmt-interface", "encryption", "authentication",
        ),
    ),
    FortiGateEndpoint.INTERFACES: EndpointSpec(
        FortiGateEndpoint.INTERFACES,
        "/api/v2/cmdb/system/interface",
        ApiScope.VDOM,
        True,
        (
            "name", "alias", "vdom", "type", "mode", "ip", "status", "role",
            "allowaccess", "vlanid", "interface", "description", "mtu", "speed",
        ),
    ),
    FortiGateEndpoint.STATIC_ROUTES: EndpointSpec(
        FortiGateEndpoint.STATIC_ROUTES,
        "/api/v2/cmdb/router/static",
        ApiScope.VDOM,
        True,
        ("seq-num", "dst", "gateway", "device", "distance", "priority", "status", "blackhole", "comment"),
    ),
    FortiGateEndpoint.FIREWALL_POLICIES: EndpointSpec(
        FortiGateEndpoint.FIREWALL_POLICIES,
        "/api/v2/cmdb/firewall/policy",
        ApiScope.VDOM,
        True,
        (
            "policyid", "uuid", "name", "status", "srcintf", "dstintf", "srcaddr",
            "dstaddr", "service", "schedule", "action", "nat", "ippool", "poolname",
            "logtraffic", "utm-status", "ssl-ssh-profile", "av-profile",
            "webfilter-profile", "dnsfilter-profile", "application-list", "ips-sensor",
            "comments",
        ),
    ),
    FortiGateEndpoint.FIREWALL_ADDRESSES: EndpointSpec(
        FortiGateEndpoint.FIREWALL_ADDRESSES,
        "/api/v2/cmdb/firewall/address",
        ApiScope.VDOM,
        True,
        ("name", "type", "subnet", "fqdn", "interface", "associated-interface", "comment", "visibility"),
    ),
    FortiGateEndpoint.IPSEC_PHASE1: EndpointSpec(
        FortiGateEndpoint.IPSEC_PHASE1,
        "/api/v2/cmdb/vpn.ipsec/phase1-interface",
        ApiScope.VDOM,
        True,
        (
            "name", "interface", "ike-version", "type", "peertype", "remote-gw", "proposal",
            "dhgrp", "nattraversal", "dpd", "certificate", "comments",
        ),
    ),
}
