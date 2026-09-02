from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from hyperv_mcp.checkpoint import (
    CheckpointPlanRequest,
    CheckpointReceiptStore,
    build_checkpoint_plan,
    checkpoint_verification,
    deterministic_checkpoint_name,
    parse_preflight,
)
from hyperv_mcp.checkpoint_scripts import CHECKPOINT_SCRIPTS, CheckpointScriptId
from hyperv_mcp.config import Settings
from hyperv_mcp.contract import TOOL_POLICIES

_VM_ID = "11111111-2222-3333-4444-555555555555"
_CHECKPOINT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _request(**overrides: str) -> CheckpointPlanRequest:
    values = {
        "target_id": "hv01",
        "vm_name": "APP01",
        "label": "pre-update",
        "idempotency_key": "update/app01/2026-09-02",
    }
    values.update(overrides)
    return CheckpointPlanRequest(**values)


def _raw_preflight(
    *,
    checkpoint_type: str = "ProductionOnly",
    state: str = "Running",
    checkpoints: list[dict[str, object]] | None = None,
    clustered: bool = False,
) -> dict[str, object]:
    items = checkpoints or []
    return {
        "items": [
            {
                "vmId": _VM_ID,
                "vmName": "APP01",
                "state": state,
                "status": "Operating normally",
                "clustered": clustered,
                "checkpointType": checkpoint_type,
                "checkpointCount": len(items),
                "checkpoints": items,
                "checkpointsTruncated": False,
            }
        ],
        "nextCursor": None,
    }


def _checkpoint(index: int, name: str | None = None) -> dict[str, object]:
    return {
        "id": f"00000000-0000-0000-0000-{index:012d}",
        "name": name or f"old-{index}",
        "snapshotType": "Production",
        "creationTime": "2026-09-02T21:00:00+00:00",
    }


def test_checkpoint_name_is_deterministic_and_bound_to_idempotency() -> None:
    request = _request()
    name = deterministic_checkpoint_name(request, _VM_ID)
    assert name.startswith("pre-update--mcp-")
    assert name == deterministic_checkpoint_name(request, _VM_ID)
    assert name != deterministic_checkpoint_name(
        _request(idempotency_key="update/app01/2026-09-03"), _VM_ID
    )


def test_preflight_requires_production_only_and_safe_vm_state() -> None:
    observed = parse_preflight(_raw_preflight(), max_existing=8)
    assert observed.checkpointType == "ProductionOnly"

    with pytest.raises(ValueError, match="ProductionOnly"):
        parse_preflight(_raw_preflight(checkpoint_type="Production"), max_existing=8)
    with pytest.raises(ValueError, match="Running or Off"):
        parse_preflight(_raw_preflight(state="Saved"), max_existing=8)


def test_plan_is_high_risk_approval_bound_and_cluster_aware() -> None:
    request = _request()
    preflight = parse_preflight(
        _raw_preflight(clustered=True),
        max_existing=8,
    )
    result = build_checkpoint_plan(
        request=request,
        preflight=preflight,
        correlation_id="",
        actor="patch-agent",
        max_existing=8,
    )
    assert result["plan"]["risk"] == "high"
    assert result["plan"]["approval"]["state"] == "required"
    assert result["plan"]["pre_state"]["clustered"] is True
    assert result["approvalBinding"]["intent"]["checkpointType"] == "ProductionOnly"
    assert result["approvalBinding"]["intent"]["vmId"] == _VM_ID
    assert result["checkpointName"].startswith("pre-update--mcp-")


def test_plan_rejects_new_checkpoint_when_safety_limit_is_reached() -> None:
    request = _request()
    preflight = parse_preflight(
        _raw_preflight(checkpoints=[_checkpoint(index) for index in range(1, 9)]),
        max_existing=8,
    )
    with pytest.raises(ValueError, match="reached the configured safety limit"):
        build_checkpoint_plan(
            request=request,
            preflight=preflight,
            correlation_id="",
            actor="patch-agent",
            max_existing=8,
        )


def test_verification_requires_exact_checkpoint_and_vm_identity() -> None:
    request = _request()
    name = deterministic_checkpoint_name(request, _VM_ID)
    preflight = parse_preflight(
        _raw_preflight(
            checkpoints=[
                {
                    "id": _CHECKPOINT_ID,
                    "name": name,
                    "snapshotType": "Production",
                    "creationTime": "2026-09-02T21:00:00+00:00",
                }
            ]
        ),
        max_existing=8,
    )
    verification = checkpoint_verification(
        preflight=preflight,
        expected_vm_id=_VM_ID,
        checkpoint_name=name,
        expected_checkpoint_id=_CHECKPOINT_ID,
    )
    assert verification.passed is True
    wrong = checkpoint_verification(
        preflight=preflight,
        expected_vm_id=_VM_ID,
        checkpoint_name=name,
        expected_checkpoint_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
    )
    assert wrong.passed is False


def test_receipt_store_binds_idempotency_to_exact_checkpoint_intent(tmp_path) -> None:
    path = tmp_path / "checkpoint-receipts.json"
    store = CheckpointReceiptStore(path)
    request = _request()
    name = deterministic_checkpoint_name(request, _VM_ID)
    receipt = store.prepare(
        idempotency_key=request.idempotency_key,
        target_id=request.target_id,
        vm_id=_VM_ID,
        checkpoint_name=name,
        pre_checkpoint_ids=[],
    )
    assert receipt["status"] == "pending"
    serialized = path.read_text(encoding="utf-8")
    assert "approval" not in serialized.casefold()

    with pytest.raises(PermissionError, match="different checkpoint intent"):
        store.prepare(
            idempotency_key=request.idempotency_key,
            target_id=request.target_id,
            vm_id=_VM_ID,
            checkpoint_name="other--mcp-0123456789ab",
            pre_checkpoint_ids=[],
        )

    verified = store.mark_verified(
        idempotency_key=request.idempotency_key,
        target_id=request.target_id,
        vm_id=_VM_ID,
        checkpoint_name=name,
        checkpoint_id=_CHECKPOINT_ID,
        creation_time=datetime.now(UTC),
    )
    assert verified["status"] == "verified"
    assert verified["checkpointId"] == _CHECKPOINT_ID


def test_receipt_store_rejects_naive_provider_timestamp(tmp_path) -> None:
    path = tmp_path / "checkpoint-receipts.json"
    store = CheckpointReceiptStore(path)
    request = _request()
    name = deterministic_checkpoint_name(request, _VM_ID)
    store.prepare(
        idempotency_key=request.idempotency_key,
        target_id=request.target_id,
        vm_id=_VM_ID,
        checkpoint_name=name,
        pre_checkpoint_ids=[],
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        store.mark_verified(
            idempotency_key=request.idempotency_key,
            target_id=request.target_id,
            vm_id=_VM_ID,
            checkpoint_name=name,
            checkpoint_id=_CHECKPOINT_ID,
            creation_time=datetime(2026, 9, 2, 21, 0, 0),
        )


def test_malformed_receipt_store_fails_closed(tmp_path) -> None:
    path = tmp_path / "checkpoint-receipts.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="malformed"):
        CheckpointReceiptStore(path).get("update/app01/2026-09-02")


def test_write_boundary_requires_separate_constrained_jea_endpoint(tmp_path) -> None:
    base = {
        "hyperv_backend_read_only": True,
        "hyperv_targets_json": json.dumps(
            {
                "hv01": {
                    "computer_name": "hv01.example.invalid",
                    "transport": "winrm",
                    "configuration_name": "FlowooxHyperVReadOnly",
                }
            }
        ),
        "hyperv_checkpoint_writes_enabled": True,
        "hyperv_checkpoint_backend_constrained": True,
        "hyperv_checkpoint_approval_secret": "x" * 32,
        "hyperv_checkpoint_receipt_store": str(tmp_path / "receipts.json"),
    }
    settings = Settings(
        **base,
        hyperv_checkpoint_targets_json=json.dumps(
            {
                "hv01": {
                    "computer_name": "hv01.example.invalid",
                    "transport": "winrm",
                    "configuration_name": "FlowooxHyperVCheckpoint",
                }
            }
        ),
    )
    settings.validate_checkpoint_write_boundary()

    same_endpoint = Settings(
        **base,
        hyperv_checkpoint_targets_json=json.dumps(
            {
                "hv01": {
                    "computer_name": "hv01.example.invalid",
                    "transport": "winrm",
                    "configuration_name": "FlowooxHyperVReadOnly",
                }
            }
        ),
    )
    with pytest.raises(ValueError, match="separate JEA"):
        same_endpoint.validate_checkpoint_write_boundary()


def test_only_fixed_checkpoint_create_script_contains_checkpoint_vm() -> None:
    preflight = CHECKPOINT_SCRIPTS[CheckpointScriptId.PREFLIGHT]
    create = CHECKPOINT_SCRIPTS[CheckpointScriptId.CREATE]
    assert "Checkpoint-VM" not in preflight
    assert "Checkpoint-VM" in create
    assert "ProductionOnly" in create
    assert "expectedVmId" in create
    assert "Remove-VMSnapshot" not in create
    assert "Restore-VMSnapshot" not in create
    assert "Set-VM" not in create
    assert "Invoke-Expression" not in "\n".join(CHECKPOINT_SCRIPTS.values())


def test_contract_declares_only_checkpoint_creation_write() -> None:
    policies = {policy.name: policy for policy in TOOL_POLICIES}
    assert policies["hyperv.checkpoint.plan"].requires_approval is True
    assert policies["hyperv.checkpoint.change"].requires_approval is True
    assert policies["hyperv.checkpoint.change"].risk.value == "high"
    assert policies["hyperv.checkpoint.verify"].risk.value == "read_only"
    assert "hyperv.checkpoint.restore" not in policies
    assert "hyperv.checkpoint.delete" not in policies
