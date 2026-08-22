from mcp_common.operations import OperationPhase, RiskLevel

from ad_mcp.contract import CONTRACT, CONTRACT_VERSION, TOOL_POLICIES, capabilities


def test_contract_is_versioned_and_explicit() -> None:
    document = capabilities()
    assert CONTRACT == "flowoox.active-directory"
    assert CONTRACT_VERSION == "1.0.0"
    assert document["contract"] == CONTRACT
    assert document["version"] == CONTRACT_VERSION
    assert {item["id"] for item in document["capabilities"]} == {
        "ad.domain.summary",
        "ad.replication.health",
        "ad.secure-channel.local",
        "ad.security.baseline",
        "ad.user.get",
        "ad.computer.get",
        "ad.group.get",
    }


def test_initial_contract_is_read_only() -> None:
    assert TOOL_POLICIES
    assert all(policy.phase == OperationPhase.OBSERVE for policy in TOOL_POLICIES)
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in TOOL_POLICIES)
    assert all(policy.requires_approval is False for policy in TOOL_POLICIES)


def test_contract_does_not_advertise_arbitrary_execution() -> None:
    ids = {policy.name for policy in TOOL_POLICIES}
    assert not any("shell" in item or "powershell" in item or "command" in item for item in ids)
