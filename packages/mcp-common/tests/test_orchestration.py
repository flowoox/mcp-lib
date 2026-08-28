from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_common.operations import OperationPhase, RiskLevel
from mcp_common.orchestration import OrchestrationStep, OrchestrationWorkflow


def _reference_path() -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "docs"
        / "infrastructure"
        / "employee-entry-reference-v1.json"
    )


def test_employee_entry_reference_is_valid_and_dependency_ordered() -> None:
    workflow = OrchestrationWorkflow.model_validate_json(
        _reference_path().read_text(encoding="utf-8")
    )

    assert workflow.workflow_id == "employee-entry-reference"
    assert workflow.execution_waves() == [
        [
            "observe-orchestrator",
            "observe-entra",
            "observe-directory-network",
            "observe-ad-domain",
        ],
        ["plan-disabled-user"],
        ["change-disabled-user"],
        ["verify-disabled-user"],
        ["evaluate-security-evidence"],
    ]

    change = next(step for step in workflow.steps if step.phase == OperationPhase.CHANGE)
    assert change.service == "ad-mcp"
    assert change.requires_approval is True
    assert change.approval_ref == "control.approvals.ad_user_create"
    assert change.idempotency_ref == "input.request.idempotency_key"


def test_orchestration_bindings_reject_literal_values() -> None:
    with pytest.raises(ValidationError, match="literals are forbidden"):
        OrchestrationStep(
            id="observe-example",
            service="example-mcp",
            operation="example.observe",
            phase=OperationPhase.OBSERVE,
            risk=RiskLevel.READ_ONLY,
            bindings={"host": "server01.internal.example"},
        )


def test_change_steps_require_approval_and_idempotency() -> None:
    with pytest.raises(ValidationError, match="idempotency_ref"):
        OrchestrationStep(
            id="change-example",
            service="example-mcp",
            operation="example.change",
            phase=OperationPhase.CHANGE,
            risk=RiskLevel.HIGH,
            lifecycle_group="example-lifecycle",
            requires_approval=True,
            approval_ref="control.approvals.example",
        )


def test_workflow_rejects_non_allowlisted_operations() -> None:
    with pytest.raises(ValidationError, match="operation is not allowlisted"):
        OrchestrationWorkflow(
            workflow_id="example-workflow",
            version="1.0.0",
            purpose="test",
            allowed_operations=["example.observe"],
            steps=[
                OrchestrationStep(
                    id="observe-example",
                    service="example-mcp",
                    operation="other.observe",
                    phase=OperationPhase.OBSERVE,
                    risk=RiskLevel.READ_ONLY,
                )
            ],
        )


def test_workflow_rejects_dependency_cycles() -> None:
    with pytest.raises(ValidationError, match="contain a cycle"):
        OrchestrationWorkflow(
            workflow_id="cycle-workflow",
            version="1.0.0",
            purpose="test",
            allowed_operations=["example.observe"],
            steps=[
                OrchestrationStep(
                    id="observe-one",
                    service="example-mcp",
                    operation="example.observe",
                    phase=OperationPhase.OBSERVE,
                    risk=RiskLevel.READ_ONLY,
                    depends_on=["observe-two"],
                ),
                OrchestrationStep(
                    id="observe-two",
                    service="example-mcp",
                    operation="example.observe",
                    phase=OperationPhase.OBSERVE,
                    risk=RiskLevel.READ_ONLY,
                    depends_on=["observe-one"],
                ),
            ],
        )
