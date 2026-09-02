from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from mcp_common.approval_grants import verify_approval_grant
from mcp_common.operations import (
    Approval,
    ApprovalState,
    AuditEvent,
    ChangePlan,
    ChangeStep,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
    StrictModel,
    Verification,
)
from mcp_common.store import AtomicJsonStore
from pydantic import Field, field_validator

_VM_NAME_RE = re.compile(r"^[^\x00-\x1f*?\[\]]{1,256}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
_CHECKPOINT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")
_RECEIPT_SCHEMA_VERSION = 1
_ALLOWED_VM_STATES = {"Running", "Off"}


class CheckpointPlanRequest(StrictModel):
    target_id: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    vm_name: str = Field(min_length=1, max_length=256)
    label: str = Field(default="pre-update", min_length=1, max_length=48)
    idempotency_key: str = Field(min_length=8, max_length=128)

    @field_validator("vm_name")
    @classmethod
    def validate_vm_name(cls, value: str) -> str:
        value = value.strip()
        if not _VM_NAME_RE.fullmatch(value):
            raise ValueError("vm_name contains wildcard or control characters")
        return value

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        value = value.strip()
        if not _LABEL_RE.fullmatch(value):
            raise ValueError("label must use only letters, digits, spaces, '.', '_', or '-'")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        context = OperationContext(actor="validation", source="hyperv-mcp", idempotency_key=value)
        assert context.idempotency_key is not None
        return context.idempotency_key

    def approval_intent(self, vm_id: str, checkpoint_name: str) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "vmId": clean_uuid(vm_id, "vm_id"),
            "vmName": self.vm_name,
            "checkpointName": clean_checkpoint_name(checkpoint_name),
            "checkpointType": "ProductionOnly",
        }


class CheckpointChangeRequest(CheckpointPlanRequest):
    expected_vm_id: str = Field(min_length=36, max_length=36)
    checkpoint_name: str = Field(min_length=1, max_length=80)
    approval_grant: str = Field(min_length=16, max_length=8192)

    @field_validator("expected_vm_id")
    @classmethod
    def validate_expected_vm_id(cls, value: str) -> str:
        return clean_uuid(value, "expected_vm_id")

    @field_validator("checkpoint_name")
    @classmethod
    def validate_checkpoint_name(cls, value: str) -> str:
        return clean_checkpoint_name(value)


class CheckpointEvidence(StrictModel):
    id: str
    name: str
    snapshotType: str
    creationTime: datetime

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return clean_uuid(value, "checkpoint id")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return clean_checkpoint_name(value)


class CheckpointPreflight(StrictModel):
    vmId: str
    vmName: str
    state: str
    status: str
    clustered: bool
    checkpointType: str
    checkpointCount: int = Field(ge=0)
    checkpoints: list[CheckpointEvidence] = Field(default_factory=list, max_length=64)
    checkpointsTruncated: bool = False

    @field_validator("vmId")
    @classmethod
    def validate_vm_id(cls, value: str) -> str:
        return clean_uuid(value, "vm id")


class CheckpointCreateEvidence(StrictModel):
    changed: bool
    vmId: str
    vmName: str
    checkpointId: str
    checkpointName: str
    snapshotType: str
    creationTime: datetime
    checkpointType: str
    clustered: bool

    @field_validator("vmId", "checkpointId")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return clean_uuid(value, "provider id")

    @field_validator("checkpointName")
    @classmethod
    def validate_checkpoint_name(cls, value: str) -> str:
        return clean_checkpoint_name(value)


def clean_uuid(value: str, field_name: str) -> str:
    try:
        return str(UUID(value.strip())).lower()
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a canonical UUID") from exc


def clean_checkpoint_name(value: str) -> str:
    value = value.strip()
    if not _CHECKPOINT_NAME_RE.fullmatch(value):
        raise ValueError("checkpoint_name contains unsupported characters")
    return value


def deterministic_checkpoint_name(request: CheckpointPlanRequest, vm_id: str) -> str:
    canonical_vm_id = clean_uuid(vm_id, "vm_id")
    material = "|".join(
        (request.target_id, canonical_vm_id, request.idempotency_key, request.label)
    ).encode()
    suffix = hashlib.sha256(material).hexdigest()[:12]
    return clean_checkpoint_name(f"{request.label}--mcp-{suffix}")


def checkpoint_target(target_id: str, vm_id: str, checkpoint_name: str) -> str:
    return (
        f"hyperv:{target_id}|vm:{clean_uuid(vm_id, 'vm_id')}|"
        f"checkpoint:{clean_checkpoint_name(checkpoint_name)}"
    )


def operation_context(
    actor: str,
    correlation_id: str,
    *,
    idempotency_key: str | None = None,
) -> OperationContext:
    actor = actor.strip()
    kwargs: dict[str, Any] = {
        "actor": actor,
        "source": "hyperv-mcp",
        "idempotency_key": idempotency_key,
    }
    value = correlation_id.strip()
    if value:
        try:
            kwargs["correlation_id"] = UUID(value)
        except ValueError as exc:
            raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(**kwargs)


def parse_preflight(
    raw: dict[str, Any],
    *,
    max_existing: int,
    expected_vm_id: str | None = None,
) -> CheckpointPreflight:
    items = raw.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise ValueError("checkpoint preflight must return exactly one VM")
    observed = CheckpointPreflight.model_validate(items[0])
    if expected_vm_id is not None and observed.vmId != clean_uuid(expected_vm_id, "expected_vm_id"):
        raise ValueError("VM identity changed after planning/approval")
    if observed.checkpointType != "ProductionOnly":
        raise ValueError(
            "automated checkpoints require the VM to be preconfigured with CheckpointType=ProductionOnly"
        )
    if observed.state not in _ALLOWED_VM_STATES:
        raise ValueError("VM must be Running or Off before checkpoint creation")
    if observed.checkpointCount > max_existing:
        raise ValueError("existing checkpoint count exceeds the configured safety limit")
    if observed.checkpointsTruncated:
        raise ValueError("checkpoint preflight evidence was truncated")
    if len(observed.checkpoints) != observed.checkpointCount:
        raise ValueError("checkpoint preflight count does not match returned checkpoint evidence")
    return observed


def matching_checkpoints(
    preflight: CheckpointPreflight,
    checkpoint_name: str,
) -> list[CheckpointEvidence]:
    name = clean_checkpoint_name(checkpoint_name)
    matches = [item for item in preflight.checkpoints if item.name == name]
    if len(matches) > 1:
        raise ValueError("multiple checkpoints use the deterministic checkpoint name")
    return matches


def build_checkpoint_plan(
    *,
    request: CheckpointPlanRequest,
    preflight: CheckpointPreflight,
    correlation_id: str,
    actor: str,
    max_existing: int,
) -> dict[str, Any]:
    checkpoint_name = deterministic_checkpoint_name(request, preflight.vmId)
    matches = matching_checkpoints(preflight, checkpoint_name)
    if not matches and preflight.checkpointCount >= max_existing:
        raise ValueError("existing checkpoint count reached the configured safety limit")
    target = checkpoint_target(request.target_id, preflight.vmId, checkpoint_name)
    context = operation_context(
        actor,
        correlation_id,
        idempotency_key=request.idempotency_key,
    )
    operation = "hyperv.checkpoint.change"
    plan = ChangePlan(
        operation=operation,
        risk=RiskLevel.HIGH,
        context=context,
        steps=[
            ChangeStep(
                action="create-production-only-checkpoint",
                target=target,
                reversible=False,
            )
        ],
        pre_state={
            "vmId": preflight.vmId,
            "vmName": preflight.vmName,
            "vmState": preflight.state,
            "clustered": preflight.clustered,
            "checkpointType": preflight.checkpointType,
            "checkpointCount": preflight.checkpointCount,
            "existingCheckpointId": matches[0].id if matches else None,
        },
        approval=Approval(
            state=ApprovalState.REQUIRED,
            reason=(
                "Creating a VM checkpoint changes production storage state and can affect "
                "application/storage behavior; explicit approval is required."
            ),
        ),
    )
    audit = AuditEvent(
        operation="hyperv.checkpoint.plan",
        phase=OperationPhase.PLAN,
        risk=RiskLevel.HIGH,
        context=context,
        target=target,
        status=OperationStatus.PLANNED,
        metadata={
            "checkpointType": "ProductionOnly",
            "clustered": preflight.clustered,
            "existingCheckpointCount": preflight.checkpointCount,
        },
    )
    return {
        "plan": plan.model_dump(mode="json"),
        "checkpointName": checkpoint_name,
        "expectedVmId": preflight.vmId,
        "approvalBinding": {
            "operation": operation,
            "target": target,
            "idempotencyKey": request.idempotency_key,
            "intent": request.approval_intent(preflight.vmId, checkpoint_name),
        },
        "audit": audit.model_dump(mode="json"),
        "alreadySatisfied": bool(matches),
    }


def checkpoint_verification(
    *,
    preflight: CheckpointPreflight,
    expected_vm_id: str,
    checkpoint_name: str,
    expected_checkpoint_id: str | None = None,
) -> Verification:
    canonical_vm_id = clean_uuid(expected_vm_id, "expected_vm_id")
    matches = matching_checkpoints(preflight, checkpoint_name)
    passed = (
        preflight.vmId == canonical_vm_id
        and preflight.checkpointType == "ProductionOnly"
        and len(matches) == 1
    )
    observed_checkpoint_id = matches[0].id if matches else None
    if expected_checkpoint_id is not None:
        passed = passed and observed_checkpoint_id == clean_uuid(
            expected_checkpoint_id, "expected_checkpoint_id"
        )
    return Verification(
        check="ProductionOnly checkpoint exists on the same immutable Hyper-V VM",
        passed=passed,
        details={
            "expectedVmId": canonical_vm_id,
            "observedVmId": preflight.vmId,
            "checkpointName": clean_checkpoint_name(checkpoint_name),
            "checkpointId": observed_checkpoint_id,
            "checkpointType": preflight.checkpointType,
            "clustered": preflight.clustered,
        },
    )


class CheckpointReceiptStore:
    """Persistent non-secret idempotency binding for checkpoint creation."""

    def __init__(self, path: str | Path):
        text = str(path).strip()
        if not text:
            raise ValueError("HYPERV_CHECKPOINT_RECEIPT_STORE must not be blank")
        self.store = AtomicJsonStore(
            text,
            default={"schemaVersion": _RECEIPT_SCHEMA_VERSION, "receipts": {}},
        )

    def _read(self) -> dict[str, Any]:
        path = self.store.path
        if not path.exists():
            return {"schemaVersion": _RECEIPT_SCHEMA_VERSION, "receipts": {}}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("checkpoint receipt store is malformed") from exc
        if not isinstance(document, dict) or document.get("schemaVersion") != _RECEIPT_SCHEMA_VERSION:
            raise RuntimeError("checkpoint receipt store schema is unsupported")
        if not isinstance(document.get("receipts"), dict):
            raise RuntimeError("checkpoint receipt store receipts are malformed")
        return document

    def get(self, idempotency_key: str) -> dict[str, Any] | None:
        key = CheckpointPlanRequest(
            target_id="validation",
            vm_name="validation",
            label="validation",
            idempotency_key=idempotency_key,
        ).idempotency_key
        value = self._read()["receipts"].get(key)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise RuntimeError("checkpoint receipt entry is malformed")
        return dict(value)

    def prepare(
        self,
        *,
        idempotency_key: str,
        target_id: str,
        vm_id: str,
        checkpoint_name: str,
        pre_checkpoint_ids: list[str],
    ) -> dict[str, Any]:
        key = CheckpointPlanRequest(
            target_id=target_id,
            vm_name="validation",
            label="validation",
            idempotency_key=idempotency_key,
        ).idempotency_key
        expected = {
            "targetId": target_id,
            "vmId": clean_uuid(vm_id, "vm_id"),
            "checkpointName": clean_checkpoint_name(checkpoint_name),
        }
        document = self._read()
        receipts = document["receipts"]
        existing = receipts.get(key)
        if existing is not None:
            if not isinstance(existing, dict):
                raise RuntimeError("checkpoint receipt entry is malformed")
            if any(str(existing.get(field, "")) != value for field, value in expected.items()):
                raise PermissionError(
                    "idempotency key is already bound to a different checkpoint intent"
                )
            return dict(existing)
        normalized_pre_ids = sorted({clean_uuid(value, "pre_checkpoint_id") for value in pre_checkpoint_ids})
        receipt = {
            **expected,
            "status": "pending",
            "preCheckpointIds": normalized_pre_ids,
            "checkpointId": None,
            "observedCreationTime": None,
            "preparedAt": datetime.now(UTC).isoformat(),
        }
        receipts[key] = receipt
        self.store.write(document)
        return dict(receipt)

    def mark_verified(
        self,
        *,
        idempotency_key: str,
        target_id: str,
        vm_id: str,
        checkpoint_name: str,
        checkpoint_id: str,
        creation_time: datetime,
    ) -> dict[str, Any]:
        if creation_time.tzinfo is None or creation_time.utcoffset() is None:
            raise ValueError("checkpoint creation_time must be timezone-aware")
        document = self._read()
        receipts = document["receipts"]
        existing = receipts.get(idempotency_key)
        if not isinstance(existing, dict):
            raise RuntimeError("checkpoint receipt is missing")
        expected = {
            "targetId": target_id,
            "vmId": clean_uuid(vm_id, "vm_id"),
            "checkpointName": clean_checkpoint_name(checkpoint_name),
        }
        if any(str(existing.get(field, "")) != value for field, value in expected.items()):
            raise PermissionError("checkpoint receipt binding changed")
        receipt = dict(existing)
        receipt["status"] = "verified"
        receipt["checkpointId"] = clean_uuid(checkpoint_id, "checkpoint_id")
        receipt["observedCreationTime"] = creation_time.astimezone(UTC).isoformat()
        receipts[idempotency_key] = receipt
        self.store.write(document)
        return dict(receipt)


def authorize_checkpoint_change(
    *,
    request: CheckpointChangeRequest,
    approval_secret: str,
) -> Approval:
    expected_name = deterministic_checkpoint_name(request, request.expected_vm_id)
    if request.checkpoint_name != expected_name:
        raise ValueError("checkpoint_name does not match the deterministic approved name")
    return verify_approval_grant(
        request.approval_grant,
        approval_secret,
        operation="hyperv.checkpoint.change",
        target=checkpoint_target(
            request.target_id,
            request.expected_vm_id,
            request.checkpoint_name,
        ),
        idempotency_key=request.idempotency_key,
        intent=request.approval_intent(request.expected_vm_id, request.checkpoint_name),
    )


def change_response(
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    request: CheckpointChangeRequest,
    changed: bool,
    output: dict[str, Any],
    approval: Approval,
    verification: Verification,
) -> dict[str, Any]:
    context = operation_context(
        actor,
        correlation_id,
        idempotency_key=request.idempotency_key,
    )
    status = OperationStatus.SUCCEEDED if verification.passed else OperationStatus.FAILED
    result = OperationResult(
        operation="hyperv.checkpoint.change",
        phase=OperationPhase.CHANGE,
        status=status,
        context=context,
        changed=changed,
        output=output,
        verification=[verification],
    )
    audit = AuditEvent(
        operation="hyperv.checkpoint.change",
        phase=OperationPhase.CHANGE,
        risk=RiskLevel.HIGH,
        context=context,
        target=checkpoint_target(
            request.target_id,
            request.expected_vm_id,
            request.checkpoint_name,
        ),
        status=status,
        changed=changed,
        metadata={
            "reason": reason.strip()[:1000],
            "approvalState": approval.state.value,
            "approver": approval.approver,
            "verificationPassed": verification.passed,
        },
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


def verify_response(
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    target_id: str,
    expected_vm_id: str,
    checkpoint_name: str,
    verification: Verification,
) -> dict[str, Any]:
    context = operation_context(actor, correlation_id)
    status = OperationStatus.SUCCEEDED if verification.passed else OperationStatus.FAILED
    result = OperationResult(
        operation="hyperv.checkpoint.verify",
        phase=OperationPhase.VERIFY,
        status=status,
        context=context,
        verification=[verification],
    )
    audit = AuditEvent(
        operation="hyperv.checkpoint.verify",
        phase=OperationPhase.VERIFY,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=checkpoint_target(target_id, expected_vm_id, checkpoint_name),
        status=status,
        metadata={"reason": reason.strip()[:1000]},
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload
