from entra_mcp.endpoints import EntraEndpoint
from entra_mcp.observations import project_collection


def test_user_projection_drops_unselected_fields() -> None:
    payload = {
        "value": [
            {
                "id": "u1",
                "displayName": "Alice",
                "userPrincipalName": "alice@example.test",
                "accountEnabled": True,
                "passwordProfile": {"password": "never-return"},
                "custom": "drop-me",
            }
        ]
    }
    result = project_collection(EntraEndpoint.USERS, payload, limit=10)
    item = result["items"][0]
    assert item["id"] == "u1"
    assert item["displayName"] == "Alice"
    assert "passwordProfile" not in item
    assert "custom" not in item


def test_conditional_access_projection_redacts_secret_shaped_nested_fields() -> None:
    payload = {
        "value": [
            {
                "id": "p1",
                "displayName": "Require MFA",
                "state": "enabled",
                "conditions": {"users": {"includeUsers": ["All"], "secretToken": "bad"}},
            }
        ]
    }
    result = project_collection(EntraEndpoint.CONDITIONAL_ACCESS, payload, limit=10)
    assert result["items"][0]["conditions"]["users"]["secretToken"] == "[REDACTED]"
    assert result["redactedFields"] == 1
