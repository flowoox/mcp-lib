from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .endpoints import ENDPOINTS, FortiGateEndpoint

_REDACTED = "[REDACTED]"
_MAX_STRING_LENGTH = 2048
_MAX_NESTED_ITEMS = 128
_MAX_DEPTH = 8
_SECRET_SUFFIXES = (
    "password", "passwd", "passphrase", "secret", "token", "privatekey", "apikey", "community"
)
_SECRET_EXACT = {"authkey", "enckey", "psk", "psksecret"}

_PROJECTIONS: dict[FortiGateEndpoint, dict[str, tuple[str, ...]]] = {
    FortiGateEndpoint.SYSTEM_STATUS: {
        "hostname": ("hostname", "host-name"),
        "modelName": ("model_name", "model-name"),
        "modelNumber": ("model_number", "model-number"),
        "model": ("model", "platform_type", "platform-type"),
        "logDiskStatus": ("log_disk_status", "log-disk-status"),
        "uptime": ("uptime",),
        "currentTime": ("current_time", "current-time", "currenttime"),
        "haMode": ("ha_mode", "ha-mode"),
        "vdomMode": ("vdom_mode", "vdom-mode"),
        "strongCrypto": ("strong_crypto", "strong-crypto"),
    },
    FortiGateEndpoint.HA_CONFIGURATION: {
        "mode": ("mode",), "groupName": ("group-name", "group_name"),
        "groupId": ("group-id", "group_id"), "priority": ("priority",),
        "override": ("override",), "sessionPickup": ("session-pickup", "session_pickup"),
        "heartbeatDevices": ("hbdev",), "monitoredInterfaces": ("monitor",),
        "unicastHeartbeat": ("unicast-hb", "unicast_hb"),
        "unicastPeer": ("unicast-hb-peerip", "unicast_hb_peerip"),
        "managementStatus": ("ha-mgmt-status", "ha_mgmt_status"),
        "managementInterface": ("ha-mgmt-interface", "ha_mgmt_interface"),
        "encryption": ("encryption",), "authentication": ("authentication",),
    },
    FortiGateEndpoint.INTERFACES: {
        "name": ("name", "_mkey"), "alias": ("alias",), "vdom": ("vdom",),
        "type": ("type",), "mode": ("mode",), "ip": ("ip",), "status": ("status",),
        "role": ("role",), "allowAccess": ("allowaccess", "allow-access"),
        "vlanId": ("vlanid", "vlan-id"), "parentInterface": ("interface",),
        "description": ("description",), "mtu": ("mtu",), "speed": ("speed",),
    },
    FortiGateEndpoint.STATIC_ROUTES: {
        "sequence": ("seq-num", "seq_num", "_mkey"), "destination": ("dst",),
        "gateway": ("gateway",), "device": ("device",), "distance": ("distance",),
        "priority": ("priority",), "status": ("status",), "blackhole": ("blackhole",),
        "comment": ("comment",),
    },
    FortiGateEndpoint.FIREWALL_POLICIES: {
        "policyId": ("policyid", "policy-id", "_mkey"), "uuid": ("uuid",),
        "name": ("name",), "status": ("status",), "sourceInterfaces": ("srcintf",),
        "destinationInterfaces": ("dstintf",), "sourceAddresses": ("srcaddr",),
        "destinationAddresses": ("dstaddr",), "services": ("service",),
        "schedule": ("schedule",), "action": ("action",), "nat": ("nat",),
        "ipPool": ("ippool",), "poolNames": ("poolname",), "logTraffic": ("logtraffic",),
        "utmStatus": ("utm-status", "utm_status"),
        "sslSshProfile": ("ssl-ssh-profile", "ssl_ssh_profile"),
        "antivirusProfile": ("av-profile", "av_profile"),
        "webFilterProfile": ("webfilter-profile", "webfilter_profile"),
        "dnsFilterProfile": ("dnsfilter-profile", "dnsfilter_profile"),
        "applicationList": ("application-list", "application_list"),
        "ipsSensor": ("ips-sensor", "ips_sensor"), "comments": ("comments",),
    },
    FortiGateEndpoint.FIREWALL_ADDRESSES: {
        "name": ("name", "_mkey"), "type": ("type",), "subnet": ("subnet",),
        "fqdn": ("fqdn",), "interface": ("interface", "associated-interface"),
        "comment": ("comment",), "visibility": ("visibility",),
    },
    FortiGateEndpoint.IPSEC_PHASE1: {
        "name": ("name", "_mkey"), "interface": ("interface",),
        "ikeVersion": ("ike-version", "ike_version"), "type": ("type",),
        "peerType": ("peertype", "peer-type"), "remoteGateway": ("remote-gw", "remote_gw"),
        "proposal": ("proposal",), "dhGroups": ("dhgrp",),
        "natTraversal": ("nattraversal", "nat-traversal"), "dpd": ("dpd",),
        "certificate": ("certificate",), "comments": ("comments",),
    },
}


@dataclass
class SanitizationState:
    redacted: int = 0
    truncated: bool = False


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _secret_key(value: str) -> bool:
    normalized = _normalized_key(value)
    return normalized in _SECRET_EXACT or normalized.endswith(_SECRET_SUFFIXES)


def _sanitize(value: Any, state: SanitizationState, *, key: str = "", depth: int = 0) -> Any:
    if _secret_key(key):
        state.redacted += 1
        return _REDACTED
    if depth > _MAX_DEPTH:
        state.truncated = True
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if value.lstrip().startswith("ENC "):
            state.redacted += 1
            return _REDACTED
        if len(value) > _MAX_STRING_LENGTH:
            state.truncated = True
            return value[:_MAX_STRING_LENGTH] + "…"
        return value
    if isinstance(value, Mapping):
        items = list(value.items())
        if len(items) > _MAX_NESTED_ITEMS:
            items = items[:_MAX_NESTED_ITEMS]
            state.truncated = True
        return {
            str(item_key): _sanitize(item_value, state, key=str(item_key), depth=depth + 1)
            for item_key, item_value in items
        }
    if isinstance(value, (list, tuple)):
        items = list(value)
        if len(items) > _MAX_NESTED_ITEMS:
            items = items[:_MAX_NESTED_ITEMS]
            state.truncated = True
        return [_sanitize(item, state, depth=depth + 1) for item in items]
    rendered = str(value)
    if len(rendered) > _MAX_STRING_LENGTH:
        state.truncated = True
        return rendered[:_MAX_STRING_LENGTH] + "…"
    return rendered


def _first(record: Mapping[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        if alias in record:
            return record[alias]
    normalized = {_normalized_key(str(key)): value for key, value in record.items()}
    for alias in aliases:
        key = _normalized_key(alias)
        if key in normalized:
            return normalized[key]
    return None


def _project_record(endpoint: FortiGateEndpoint, record: Mapping[str, Any], state: SanitizationState) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for canonical, aliases in _PROJECTIONS[endpoint].items():
        value = _first(record, aliases)
        if value is not None:
            output[canonical] = _sanitize(value, state, key=canonical)
    return output


def _collection_records(results: Any) -> list[Mapping[str, Any]]:
    if isinstance(results, list):
        return [item for item in results if isinstance(item, Mapping)]
    if not isinstance(results, Mapping):
        return []
    if results and all(isinstance(item, Mapping) for item in results.values()):
        records: list[Mapping[str, Any]] = []
        for key, value in results.items():
            record = dict(value)
            record.setdefault("_mkey", key)
            records.append(record)
        return records
    return [results]


def project_response(endpoint: FortiGateEndpoint, payload: Mapping[str, Any], *, limit: int) -> dict[str, Any]:
    spec = ENDPOINTS[endpoint]
    if isinstance(limit, bool) or limit < 1:
        raise ValueError("limit must be a positive integer")
    state = SanitizationState()
    results = payload.get("results")
    output: dict[str, Any] = {
        "endpoint": endpoint.value,
        "scope": spec.scope.value,
        "vdom": _sanitize(payload.get("vdom"), state, key="vdom"),
        "device": {
            key: _sanitize(payload.get(key), state, key=key)
            for key in ("serial", "version", "build")
            if payload.get(key) is not None
        },
    }
    if spec.collection:
        records = _collection_records(results)
        selected = records[:limit]
        output["items"] = [_project_record(endpoint, record, state) for record in selected]
        output["returned"] = len(selected)
        output["availableInPayload"] = len(records)
    else:
        if not isinstance(results, Mapping):
            raise ValueError(f"FortiGate endpoint {endpoint.value} returned invalid results")
        output["data"] = _project_record(endpoint, results, state)
        output["returned"] = 1
    output["redactedFields"] = state.redacted
    output["sanitizationTruncated"] = state.truncated
    return output
