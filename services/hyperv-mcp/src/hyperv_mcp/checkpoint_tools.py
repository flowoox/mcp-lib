from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.operations import Verification

from .checkpoint import (
    CheckpointChangeRequest,
    CheckpointCreateEvidence,
    CheckpointPlanRequest,
    CheckpointReceiptStore,
    authorize_checkpoint_change,
    build_checkpoint_plan,
    change_response,
    checkpoint_verification,
    deterministic_checkpoint_name,
    matching_checkpoints,
    parse_preflight,
    verify_response,
)
from .checkpoint_runner import CheckpointPowerShellRunner
from .checkpoint_scripts import CheckpointScriptId
from .config import HyperVTarget, Settings


def _reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return value


def _target(settings: Settings, target_id: str) -> HyperVTarget:
    targets = settings.checkpoint_targets
    try:
        return targets[target_id]
    except KeyError as exc:
        raise PermissionError(
            "checkpoint target is not in HYPERV_CHECKPOINT_TARGETS_JSON"
        ) from exc


def _store(settings: Settings) -> CheckpointReceiptStore:
    return CheckpointReceiptStore(settings.hyperv_checkpoint_receipt_store)


async def _run_preflight(
    runner: CheckpointPowerShellRunner,
    settings: Settings,
    target: HyperVTarget,
    vm_name: str,
) -> dict[str, Any]:
    raw, _ = await asyncio.to_thread(
        runner.run,
        CheckpointScriptId.PREFLIGHT,
        target,
        {
            "vmName": vm_name,
            "maxExisting": settings.hyperv_checkpoint_max_existing,
        },
        timeout_seconds=settings.hyperv_checkpoint_timeout_seconds,
        max_response_bytes=settings.hyperv_checkpoint_max_response_bytes,
    )
    return raw


def _verified_receipt_matches(
    receipt: dict[str, Any] | None,
    *,
    target_id: str,
    vm_id: str,
    checkpoint_name: str,
    checkpoint_id: str,
) -> bool:
    if receipt is None or receipt.get("status") != "verified":
        return False
    return (
        str(receipt.get("targetId", "")) == target_id
        and str(receipt.get("vmId", "")) == vm_id
        and str(receipt.get("checkpointName", "")) == checkpoint_name
        and str(receipt.get("checkpointId", "")) == checkpoint_id
    )


def register_checkpoint_tools(
    mcp: FastMCP,
    *,
    settings: Settings,
    runner: CheckpointPowerShellRunner | None = None,
) -> None:
    """Register the separately gated ProductionOnly checkpoint lifecycle."""

    runner = runner or CheckpointPowerShellRunner(settings.hyperv_powershell_executable)

    @mcp.tool()
    async def hyperv_plan_checkpoint(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        idempotency_key: str,
        label: str = "pre-update",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Plan one deterministic ProductionOnly checkpoint before a controlled change."""

        _reason(reason)
        request = CheckpointPlanRequest(
            target_id=target_id,
            vm_name=vm_name,
            label=label,
            idempotency_key=idempotency_key,
        )
        target = _target(settings, request.target_id)
        raw = await _run_preflight(runner, settings, target, request.vm_name)
        preflight = parse_preflight(
            raw,
            max_existing=settings.hyperv_checkpoint_max_existing,
        )
        checkpoint_name = deterministic_checkpoint_name(request, preflight.vmId)
        matches = matching_checkpoints(preflight, checkpoint_name)
        receipt = None
        if settings.hyperv_checkpoint_receipt_store.strip():
            receipt = _store(settings).get(request.idempotency_key)
        if matches and not _verified_receipt_matches(
            receipt,
            target_id=request.target_id,
            vm_id=preflight.vmId,
            checkpoint_name=checkpoint_name,
            checkpoint_id=matches[0].id,
        ):
            raise RuntimeError(
                "deterministic checkpoint name already exists without a matching verified receipt"
            )
        result = build_checkpoint_plan(
            request=request,
            preflight=preflight,
            correlation_id=correlation_id,
            actor=actor,
        )
        result["alreadySatisfied"] = bool(matches)
        result["clusterRouting"] = {
            "clustered": preflight.clustered,
            "requireCurrentOwnerTarget": preflight.clustered,
            "ownerResolution": (
                "resolve the current cluster-group owner through failovercluster-mcp before change"
                if preflight.clustered
                else "not_required"
            ),
        }
        return result

    @mcp.tool()
    async def hyperv_change_checkpoint(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        expected_vm_id: str,
        checkpoint_name: str,
        idempotency_key: str,
        approval_grant: str,
        label: str = "pre-update",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Create one approved deterministic ProductionOnly checkpoint and verify readback."""

        reason = _reason(reason)
        if not settings.hyperv_checkpoint_writes_enabled:
            raise PermissionError(
                "checkpoint creation is disabled by HYPERV_CHECKPOINT_WRITES_ENABLED=false"
            )
        settings.validate_checkpoint_write_boundary()
        request = CheckpointChangeRequest(
            target_id=target_id,
            vm_name=vm_name,
            label=label,
            expected_vm_id=expected_vm_id,
            checkpoint_name=checkpoint_name,
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        target = _target(settings, request.target_id)
        approval = authorize_checkpoint_change(
            request=request,
            approval_secret=settings.hyperv_checkpoint_approval_secret,
        )
        raw = await _run_preflight(runner, settings, target, request.vm_name)
        preflight = parse_preflight(
            raw,
            max_existing=settings.hyperv_checkpoint_max_existing,
            expected_vm_id=request.expected_vm_id,
        )
        expected_name = deterministic_checkpoint_name(request, preflight.vmId)
        if expected_name != request.checkpoint_name:
            raise ValueError("checkpoint name changed after planning/approval")

        matches = matching_checkpoints(preflight, request.checkpoint_name)
        store = _store(settings)
        existing_receipt = store.get(request.idempotency_key)
        if matches and existing_receipt is None:
            raise RuntimeError(
                "checkpoint exists without a matching idempotency receipt; refusing implicit recovery"
            )
        receipt = store.prepare(
            idempotency_key=request.idempotency_key,
            target_id=request.target_id,
            vm_id=request.expected_vm_id,
            checkpoint_name=request.checkpoint_name,
            pre_checkpoint_ids=[item.id for item in preflight.checkpoints],
        )

        if receipt.get("status") == "verified":
            checkpoint_id = str(receipt.get("checkpointId") or "")
            verification = checkpoint_verification(
                preflight=preflight,
                expected_vm_id=request.expected_vm_id,
                checkpoint_name=request.checkpoint_name,
                expected_checkpoint_id=checkpoint_id,
            )
            if not verification.passed:
                raise RuntimeError(
                    "verified checkpoint receipt conflicts with current Hyper-V state"
                )
            return change_response(
                actor=actor,
                reason=reason,
                correlation_id=correlation_id,
                request=request,
                changed=False,
                output={
                    "vmId": request.expected_vm_id,
                    "checkpointId": checkpoint_id,
                    "checkpointName": request.checkpoint_name,
                    "idempotentReceipt": True,
                },
                approval=approval,
                verification=verification,
            )

        if matches:
            pre_ids = receipt.get("preCheckpointIds")
            if not isinstance(pre_ids, list):
                raise RuntimeError("pending checkpoint receipt is malformed")
            if matches[0].id in {str(item) for item in pre_ids}:
                raise RuntimeError(
                    "pending receipt refers to a checkpoint that already existed before mutation"
                )
            verification = checkpoint_verification(
                preflight=preflight,
                expected_vm_id=request.expected_vm_id,
                checkpoint_name=request.checkpoint_name,
                expected_checkpoint_id=matches[0].id,
            )
            if not verification.passed:
                raise RuntimeError("pending checkpoint receipt could not be recovered safely")
            store.mark_verified(
                idempotency_key=request.idempotency_key,
                target_id=request.target_id,
                vm_id=request.expected_vm_id,
                checkpoint_name=request.checkpoint_name,
                checkpoint_id=matches[0].id,
                creation_time=matches[0].creationTime,
            )
            return change_response(
                actor=actor,
                reason=reason,
                correlation_id=correlation_id,
                request=request,
                changed=False,
                output={
                    "vmId": request.expected_vm_id,
                    "checkpointId": matches[0].id,
                    "checkpointName": request.checkpoint_name,
                    "recoveredPendingReceipt": True,
                },
                approval=approval,
                verification=verification,
            )

        raw_create, _ = await asyncio.to_thread(
            runner.run,
            CheckpointScriptId.CREATE,
            target,
            {
                "vmName": request.vm_name,
                "expectedVmId": request.expected_vm_id,
                "snapshotName": request.checkpoint_name,
                "maxExisting": settings.hyperv_checkpoint_max_existing,
            },
            timeout_seconds=settings.hyperv_checkpoint_timeout_seconds,
            max_response_bytes=settings.hyperv_checkpoint_max_response_bytes,
        )
        create_items = raw_create.get("items")
        if not isinstance(create_items, list) or len(create_items) != 1:
            raise RuntimeError("checkpoint create operation returned invalid evidence")
        created = CheckpointCreateEvidence.model_validate(create_items[0])
        if created.vmId != request.expected_vm_id:
            raise RuntimeError("checkpoint create evidence returned a different VM id")
        if created.checkpointName != request.checkpoint_name:
            raise RuntimeError("checkpoint create evidence returned a different checkpoint name")
        if created.checkpointType != "ProductionOnly":
            raise RuntimeError("checkpoint create evidence lost the ProductionOnly boundary")

        readback_raw = await _run_preflight(runner, settings, target, request.vm_name)
        readback = parse_preflight(
            readback_raw,
            max_existing=settings.hyperv_checkpoint_max_existing,
            expected_vm_id=request.expected_vm_id,
        )
        verification = checkpoint_verification(
            preflight=readback,
            expected_vm_id=request.expected_vm_id,
            checkpoint_name=request.checkpoint_name,
            expected_checkpoint_id=created.checkpointId,
        )
        if verification.passed:
            store.mark_verified(
                idempotency_key=request.idempotency_key,
                target_id=request.target_id,
                vm_id=request.expected_vm_id,
                checkpoint_name=request.checkpoint_name,
                checkpoint_id=created.checkpointId,
                creation_time=created.creationTime,
            )
        return change_response(
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            request=request,
            changed=created.changed,
            output={
                "vmId": created.vmId,
                "checkpointId": created.checkpointId,
                "checkpointName": created.checkpointName,
                "snapshotType": created.snapshotType,
                "creationTime": created.creationTime.isoformat(),
                "clustered": created.clustered,
            },
            approval=approval,
            verification=verification,
        )

    @mcp.tool()
    async def hyperv_verify_checkpoint(
        actor: str,
        reason: str,
        target_id: str,
        vm_name: str,
        expected_vm_id: str,
        checkpoint_name: str,
        idempotency_key: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Verify checkpoint existence, VM identity, ProductionOnly state and receipt binding."""

        reason = _reason(reason)
        request = CheckpointPlanRequest(
            target_id=target_id,
            vm_name=vm_name,
            label="verification",
            idempotency_key=idempotency_key,
        )
        target = _target(settings, request.target_id)
        receipt = _store(settings).get(request.idempotency_key)
        if receipt is None or receipt.get("status") != "verified":
            raise RuntimeError("no verified checkpoint receipt exists for this idempotency key")
        if str(receipt.get("vmId", "")) != expected_vm_id:
            raise PermissionError("checkpoint receipt is bound to a different VM")
        if str(receipt.get("checkpointName", "")) != checkpoint_name:
            raise PermissionError("checkpoint receipt is bound to a different checkpoint name")
        checkpoint_id = str(receipt.get("checkpointId") or "")
        raw = await _run_preflight(runner, settings, target, request.vm_name)
        preflight = parse_preflight(
            raw,
            max_existing=settings.hyperv_checkpoint_max_existing,
            expected_vm_id=expected_vm_id,
        )
        verification = checkpoint_verification(
            preflight=preflight,
            expected_vm_id=expected_vm_id,
            checkpoint_name=checkpoint_name,
            expected_checkpoint_id=checkpoint_id,
        )
        return verify_response(
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            target_id=request.target_id,
            expected_vm_id=expected_vm_id,
            checkpoint_name=checkpoint_name,
            verification=verification,
        )
