from mcp_common.operations import OperationPhase, RiskLevel

from ad_mcp.contract import CONTRACT, CONTRACT_VERSION, TOOL_POLICIES, capabilities


def test_contract_is_versioned_and_explicit() -> None:
    document = capabilities()
    assert CONTRACT == "flowoox.active-directory"
    assert CONTRACT_VERSION == "1.2.0"
    assert document["contract"] == CONTRACT
    assert document["version"] == CONTRACT_VERSION
    assert {item["id"] for item in document["capabilities"]} == {
        "ad.domain.summary",
        "ad.replication.health",
        "ad.dns.discovery",
        "ad.secure-channel.local",
        "ad.security.baseline",
        "ad.user.get",
        "ad.user.groups",
        "ad.computer.get",
        "ad.group.get",
        "ad.ou.list",
        "ad.user.enabled.plan",
        "ad.user.enabled.change",
        "ad.user.enabled.verify",
        "ad.user.group-membership.plan",
        "ad.user.group-membership.change",
        "ad.user.group-membership.verify",
    }


def test_write_contract_requires_approval_and_is_fail_closed_by_default() -> None:
    document = capabilities()
    assert document["runtime"]["writes_enabled"] is False
    change_policies = [
        policy for policy in TOOL_POLICIES if policy.phase == OperationPhase.CHANGE
    ]
    assert change_policies
    assert all(policy.risk == RiskLevel.HIGH for policy in change_policies)
    assert all(policy.requires_approval is True for policy in change_policies)
    observe_policies = [
        policy for policy in TOOL_POLICIES if policy.phase == OperationPhase.OBSERVE
    ]
    assert all(policy.risk == RiskLevel.READ_ONLY for policy in observe_policies)


def test_contract_reports_runtime_write_enablement_without_changing_contract_version() -> None:
    enabled = capabilities(writes_enabled=True)
    assert enabled["version"] == CONTRACT_VERSION
    assert enabled["runtime"]["writes_enabled"] is True


def test_contract_does_not_advertise_arbitrary_execution() -> None:
    ids = {policy.name for policy in TOOL_POLICIES}
    assert not any("shell" in item or "powershell" in item or "command" in item for item in ids)
