from __future__ import annotations

import re
from collections import defaultdict

from pydantic import Field, field_validator, model_validator

from .operations import OperationPhase, RiskLevel, StrictModel

_STEP_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_REFERENCE_RE = re.compile(r"^(input|steps|control)\.([A-Za-z][A-Za-z0-9_.-]{0,255})$")
_BINDING_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class OrchestrationStep(StrictModel):
    """One declarative invocation of a specialized MCP operation.

    Bindings are references only. Literal credentials, topology or policy values therefore stay
    outside the public workflow definition and are resolved by the deployment/orchestrator.
    """

    id: str = Field(pattern=_STEP_ID_RE.pattern)
    service: str = Field(pattern=_SERVICE_RE.pattern)
    operation: str = Field(pattern=_OPERATION_RE.pattern)
    phase: OperationPhase
    risk: RiskLevel
    depends_on: list[str] = Field(default_factory=list, max_length=20)
    bindings: dict[str, str] = Field(default_factory=dict, max_length=50)
    lifecycle_group: str | None = Field(default=None, pattern=_STEP_ID_RE.pattern)
    requires_approval: bool = False
    approval_ref: str | None = None
    idempotency_ref: str | None = None

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("depends_on entries must be unique")
        if any(not _STEP_ID_RE.fullmatch(item) for item in value):
            raise ValueError("depends_on contains an invalid step id")
        return value

    @field_validator("bindings")
    @classmethod
    def validate_bindings(cls, value: dict[str, str]) -> dict[str, str]:
        for key, reference in value.items():
            if not _BINDING_KEY_RE.fullmatch(key):
                raise ValueError(f"invalid binding key: {key}")
            if not _REFERENCE_RE.fullmatch(reference):
                raise ValueError(
                    f"binding {key} must reference input.*, steps.* or control.*; literals are forbidden"
                )
        return value

    @field_validator("approval_ref", "idempotency_ref")
    @classmethod
    def validate_optional_reference(cls, value: str | None) -> str | None:
        if value is not None and not _REFERENCE_RE.fullmatch(value):
            raise ValueError("orchestration control references must use input.*, steps.* or control.*")
        return value

    @model_validator(mode="after")
    def validate_phase_controls(self) -> OrchestrationStep:
        if self.id in self.depends_on:
            raise ValueError("a step cannot depend on itself")

        if self.phase in {OperationPhase.OBSERVE, OperationPhase.VERIFY}:
            if self.risk != RiskLevel.READ_ONLY:
                raise ValueError("observe and verify orchestration steps must be read_only")
        elif self.risk == RiskLevel.READ_ONLY:
            raise ValueError("plan and change orchestration steps cannot use read_only risk")

        if self.phase in {OperationPhase.PLAN, OperationPhase.CHANGE}:
            if self.lifecycle_group is None:
                raise ValueError("plan and change steps require a lifecycle_group")
            if self.idempotency_ref is None:
                raise ValueError("plan and change steps require an idempotency_ref")

        if self.phase == OperationPhase.CHANGE:
            if not self.requires_approval:
                raise ValueError("change steps require an explicit approval gate")
            if self.approval_ref is None:
                raise ValueError("change steps require an approval_ref")
        elif self.approval_ref is not None:
            raise ValueError("approval_ref is only valid on change steps")

        return self


class OrchestrationWorkflow(StrictModel):
    """Product-neutral workflow that coordinates specialized MCP authorities."""

    schema_version: int = Field(default=1, ge=1, le=1)
    workflow_id: str = Field(pattern=_STEP_ID_RE.pattern)
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    purpose: str = Field(min_length=1, max_length=1000)
    required_inputs: list[str] = Field(default_factory=list, max_length=100)
    allowed_operations: list[str] = Field(min_length=1, max_length=100)
    steps: list[OrchestrationStep] = Field(min_length=1, max_length=100)

    @field_validator("required_inputs")
    @classmethod
    def validate_inputs(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("required_inputs must be unique")
        for item in value:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,255}", item):
                raise ValueError(f"invalid required input: {item}")
        return value

    @field_validator("allowed_operations")
    @classmethod
    def validate_operation_allowlist(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed_operations must be unique")
        if any(not _OPERATION_RE.fullmatch(item) for item in value):
            raise ValueError("allowed_operations contains an invalid operation id")
        return value

    @model_validator(mode="after")
    def validate_workflow(self) -> OrchestrationWorkflow:
        step_by_id = {step.id: step for step in self.steps}
        if len(step_by_id) != len(self.steps):
            raise ValueError("step ids must be unique")

        allowed = set(self.allowed_operations)
        required_inputs = set(self.required_inputs)
        for step in self.steps:
            if step.operation not in allowed:
                raise ValueError(f"operation is not allowlisted: {step.operation}")
            missing_dependencies = [item for item in step.depends_on if item not in step_by_id]
            if missing_dependencies:
                raise ValueError(
                    f"step {step.id} depends on unknown steps: {', '.join(missing_dependencies)}"
                )
            for reference in [*step.bindings.values(), step.approval_ref, step.idempotency_ref]:
                if reference is None or not reference.startswith("input."):
                    continue
                input_name = reference.removeprefix("input.")
                if input_name not in required_inputs:
                    raise ValueError(
                        f"step {step.id} references undeclared input: {input_name}"
                    )

        self.execution_waves()
        self._validate_lifecycle_groups()
        return self

    def _validate_lifecycle_groups(self) -> None:
        groups: dict[str, list[OrchestrationStep]] = defaultdict(list)
        for step in self.steps:
            if step.lifecycle_group is not None:
                groups[step.lifecycle_group].append(step)

        for name, steps in groups.items():
            plans = [step for step in steps if step.phase == OperationPhase.PLAN]
            changes = [step for step in steps if step.phase == OperationPhase.CHANGE]
            verifies = [step for step in steps if step.phase == OperationPhase.VERIFY]
            if len(plans) != 1 or len(changes) != 1 or len(verifies) < 1:
                raise ValueError(
                    f"lifecycle_group {name} must contain one plan, one change and at least one verify step"
                )

            plan = plans[0]
            change = changes[0]
            if plan.service != change.service or any(step.service != change.service for step in verifies):
                raise ValueError(f"lifecycle_group {name} must stay within one specialized MCP")
            if change.idempotency_ref != plan.idempotency_ref:
                raise ValueError(f"lifecycle_group {name} must reuse one idempotency reference")
            if plan.id not in change.depends_on:
                raise ValueError(f"lifecycle_group {name} change must depend on its plan")
            if any(change.id not in verify.depends_on for verify in verifies):
                raise ValueError(f"lifecycle_group {name} verify must depend on its change")

    def execution_waves(self) -> list[list[str]]:
        """Return deterministic dependency waves and reject dependency cycles."""

        order = {step.id: index for index, step in enumerate(self.steps)}
        dependencies = {step.id: set(step.depends_on) for step in self.steps}
        remaining = set(dependencies)
        waves: list[list[str]] = []

        while remaining:
            ready = sorted(
                (step_id for step_id in remaining if not dependencies[step_id] & remaining),
                key=order.__getitem__,
            )
            if not ready:
                raise ValueError("workflow dependencies contain a cycle")
            waves.append(ready)
            remaining.difference_update(ready)

        return waves
