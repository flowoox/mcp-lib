from __future__ import annotations

from typing import Literal

from pydantic import Field

from mcp_common.operations import StrictModel


HostStateLabel = Literal["UP", "DOWN", "UNREACHABLE", "PENDING", "OTHER"]
ServiceStateLabel = Literal["OK", "WARN", "CRIT", "UNKNOWN", "PENDING", "OTHER"]


class CheckmkVersionObservation(StrictModel):
    version: str = Field(default="", max_length=128)
    edition: str = Field(default="", max_length=128)


class HostObservation(StrictModel):
    host_name: str = Field(min_length=1, max_length=255)
    state: int | None = Field(default=None, ge=0, le=255)
    state_label: HostStateLabel = "OTHER"
    acknowledged: bool | None = None
    in_downtime: bool | None = None
    is_flapping: bool | None = None
    stale: bool | None = None
    last_check: int | None = Field(default=None, ge=0)
    last_state_change: int | None = Field(default=None, ge=0)


class ServiceObservation(StrictModel):
    host_name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=512)
    state: int | None = Field(default=None, ge=0, le=255)
    state_label: ServiceStateLabel = "OTHER"
    acknowledged: bool | None = None
    in_downtime: bool | None = None
    is_flapping: bool | None = None
    stale: bool | None = None
    last_check: int | None = Field(default=None, ge=0)
    last_state_change: int | None = Field(default=None, ge=0)


class MonitoringProblemSummary(StrictModel):
    problem_hosts_returned: int = Field(ge=0)
    problem_hosts_truncated: bool
    problem_services_returned: int = Field(ge=0)
    problem_services_truncated: bool
