from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class WorkflowTagObservation(StrictModel):
    tag_id: str = Field(default="", max_length=128)
    name: str = Field(default="", max_length=256)


class WorkflowObservation(StrictModel):
    workflow_id: str = Field(min_length=1, max_length=128)
    name: str = Field(max_length=512)
    active: bool
    archived: bool | None = None
    created_at: str = Field(default="", max_length=128)
    updated_at: str = Field(default="", max_length=128)
    tags: list[WorkflowTagObservation] = Field(default_factory=list, max_length=32)


class ExecutionObservation(StrictModel):
    execution_id: str = Field(min_length=1, max_length=128)
    workflow_id: str = Field(min_length=1, max_length=128)
    status: str = Field(max_length=64)
    mode: str = Field(default="", max_length=64)
    started_at: str = Field(default="", max_length=128)
    stopped_at: str = Field(default="", max_length=128)
    wait_till: str = Field(default="", max_length=128)
    retry_of: str = Field(default="", max_length=128)
    retry_success_id: str = Field(default="", max_length=128)
    finished: bool | None = None


class ExecutionStatusSummary(StrictModel):
    total: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
