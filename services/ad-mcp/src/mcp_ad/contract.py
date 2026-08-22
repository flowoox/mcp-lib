from __future__ import annotations

CONTRACT_FAMILY = "flowoox.active-directory"
CONTRACT_VERSION = "1.0.0"
SERVICE_VERSION = "0.1.0"

CAPABILITIES = {
    "contract_family": CONTRACT_FAMILY,
    "contract_version": CONTRACT_VERSION,
    "service_version": SERVICE_VERSION,
    "mode": "read_only",
    "tools": [
        {
            "name": "ad_observe_domain_policy",
            "phase": "observe",
            "risk": "read_only",
        },
        {
            "name": "ad_find_user",
            "phase": "observe",
            "risk": "read_only",
        },
        {
            "name": "ad_get_group_members",
            "phase": "observe",
            "risk": "read_only",
        },
        {
            "name": "ad_list_domain_controllers",
            "phase": "observe",
            "risk": "read_only",
        },
        {
            "name": "ad_run_security_audit",
            "phase": "observe",
            "risk": "read_only",
        },
    ],
    "constraints": {
        "raw_ldap_filters": False,
        "arbitrary_attributes": False,
        "writes": False,
        "search_base_allowlist": True,
        "tls_required_by_default": True,
        "bounded_results": True,
    },
}
