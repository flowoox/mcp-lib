from fortigate_mcp.endpoints import FortiGateEndpoint
from fortigate_mcp.observations import project_response


def test_policy_projection_keeps_allowlisted_fields_only() -> None:
    payload = {
        "status": "success",
        "serial": "FGT123",
        "version": "v7.4.8",
        "build": 2795,
        "vdom": "root",
        "results": [
            {
                "policyid": 10,
                "name": "internet",
                "srcintf": [{"name": "lan"}],
                "dstintf": [{"name": "wan1"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "service": [{"name": "HTTPS"}],
                "action": "accept",
                "psksecret": "should-never-appear",
                "unrequested": "drop-me",
            }
        ],
    }
    result = project_response(FortiGateEndpoint.FIREWALL_POLICIES, payload, limit=10)
    item = result["items"][0]
    assert item["policyId"] == 10
    assert item["name"] == "internet"
    assert "unrequested" not in item
    assert "psksecret" not in item


def test_ipsec_projection_redacts_secret_shaped_nested_values() -> None:
    payload = {
        "status": "success",
        "vdom": "root",
        "results": [
            {
                "name": "branch-a",
                "proposal": [{"name": "aes256-sha256", "token": "secret"}],
                "psksecret": "ENC abc",
            }
        ],
    }
    result = project_response(FortiGateEndpoint.IPSEC_PHASE1, payload, limit=10)
    assert result["items"][0]["proposal"][0]["token"] == "[REDACTED]"
    assert result["redactedFields"] == 1
