from mcp_common.operations import OperationPhase, RiskLevel

from network_mcp.contract import CONTRACT, CONTRACT_VERSION, TOOL_POLICIES, capabilities


def test_contract_is_versioned_and_explicit() -> None:
    document = capabilities(
        allowed_cidrs="10.0.0.0/8,fd00::/8",
        max_ports_per_bundle=8,
        path_trace_enabled=True,
        path_trace_max_hops=20,
    )
    assert CONTRACT == "flowoox.network-diagnostics"
    assert CONTRACT_VERSION == "1.1.0"
    assert document["contract"] == CONTRACT
    assert document["version"] == CONTRACT_VERSION
    assert {item["id"] for item in document["capabilities"]} == {
        "network.dns.resolve",
        "network.tcp.reachability",
        "network.route.selection",
        "network.path.trace",
        "network.subnet.validate",
        "network.diagnostic.bundle",
    }
    assert document["runtime"]["allowed_cidrs"] == ["10.0.0.0/8", "fd00::/8"]
    assert document["runtime"]["path_trace_enabled"] is True
    assert document["runtime"]["path_trace_max_hops"] == 20


def test_contract_has_no_mutation_or_arbitrary_execution_surface() -> None:
    assert TOOL_POLICIES
    assert all(policy.phase == OperationPhase.OBSERVE for policy in TOOL_POLICIES)
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in TOOL_POLICIES)
    document = capabilities(allowed_cidrs="127.0.0.0/8", max_ports_per_bundle=4)
    assert document["runtime"]["arbitrary_shell"] is False
    assert document["runtime"]["arbitrary_url_fetch"] is False
    assert "no caller flags or shell" in document["runtime"]["path_trace_mode"]
