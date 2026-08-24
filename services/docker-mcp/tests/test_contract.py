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
        max_log_window_seconds=settings.docker_max_log_window_seconds,
        max_event_window_seconds=settings.docker_max_event_window_seconds,
        max_detail_candidates=settings.docker_diagnostic_detail_max_candidates,
    )

    assert CONTRACT == "flowoox.docker-diagnostics"
    assert CONTRACT_VERSION == "1.3.0"
    assert document["contract"] == CONTRACT
    assert {item["id"] for item in document["capabilities"]} == {
        "docker.health.observe",
        "docker.containers.list",
        "docker.containers.logs",
        "docker.containers.stats",
        "docker.images.list",
        "docker.volumes.list",
        "docker.networks.list",
        "docker.resources.inventory",
        "docker.events.list",
        "docker.diagnostics.bundle",
        "docker.diagnostics.detail",
    }
    assert all(policy.phase == OperationPhase.OBSERVE for policy in TOOL_POLICIES)
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in TOOL_POLICIES)
    assert document["runtime"]["writes_enabled"] is False
    assert document["runtime"]["arbitrary_api_path"] is False
    assert document["runtime"]["connector"]["backend_mode"] == "read_only"
    assert document["runtime"]["diagnostic_windows"]["live_log_follow"] is False
    assert document["runtime"]["diagnostic_windows"]["live_event_stream"] is False
    assert document["runtime"]["diagnostic_windows"]["live_stats_stream"] is False
    assert document["runtime"]["diagnostic_windows"]["container_stats_one_shot"] is True
    assert document["runtime"]["diagnostic_detail"] == {
        "aggregate_candidate_selection_required": True,
        "max_candidates": 3,
        "automatic_log_fetch": False,
        "automatic_event_fetch": False,
        "per_candidate_stats_samples": 1,
    }
    assert document["runtime"]["resource_minimization"] == {
        "image_labels_or_config": False,
        "volume_mountpoints_labels_or_options": False,
        "network_endpoint_addresses_labels_or_options": False,
        "raw_cgroup_stats": False,
    }


def test_capabilities_do_not_expose_backend_or_credentials() -> None:
    settings = Settings(
        docker_host="https://private-topology.example.invalid:2376",
        docker_auth_token="credential-value",
    )
    document = capabilities(
        _connector_policy(settings),
        _budget_limits(settings),
        direct_socket_override_enabled=False,
        max_log_window_seconds=settings.docker_max_log_window_seconds,
        max_event_window_seconds=settings.docker_max_event_window_seconds,
        max_detail_candidates=settings.docker_diagnostic_detail_max_candidates,
    )
    rendered = str(document)
    assert "private-topology" not in rendered
    assert "credential-value" not in rendered
