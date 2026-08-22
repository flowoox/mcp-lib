from mcp_common.operations import OperationPhase, RiskLevel

from docker_mcp.config import Settings
from docker_mcp.contract import CONTRACT, CONTRACT_VERSION, TOOL_POLICIES, capabilities
from docker_mcp.server import _budget_limits, _connector_policy


def test_contract_is_versioned_explicit_and_read_only() -> None:
    settings = Settings()
    document = capabilities(
        _connector_policy(settings),
        _budget_limits(settings),
        direct_socket_override_enabled=False,
    )

    assert CONTRACT == "flowoox.docker-diagnostics"
    assert CONTRACT_VERSION == "1.0.0"
    assert document["contract"] == CONTRACT
    assert {item["id"] for item in document["capabilities"]} == {
        "docker.health.observe",
        "docker.containers.list",
        "docker.diagnostics.bundle",
    }
    assert all(policy.phase == OperationPhase.OBSERVE for policy in TOOL_POLICIES)
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in TOOL_POLICIES)
    assert document["runtime"]["writes_enabled"] is False
    assert document["runtime"]["arbitrary_api_path"] is False
    assert document["runtime"]["connector"]["backend_mode"] == "read_only"


def test_capabilities_do_not_expose_backend_or_credentials() -> None:
    settings = Settings(
        docker_host="https://private-topology.example.invalid:2376",
        docker_auth_token="credential-value",
    )
    document = capabilities(
        _connector_policy(settings),
        _budget_limits(settings),
        direct_socket_override_enabled=False,
    )
    rendered = str(document)
    assert "private-topology" not in rendered
    assert "credential-value" not in rendered
