from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class AgentObservation(StrictModel):
    agent_id: str = Field(min_length=1, max_length=16)
    name: str = Field(default="", max_length=128)
    status: str = Field(default="", max_length=32)
    os_name: str = Field(default="", max_length=128)
    os_platform: str = Field(default="", max_length=64)
    os_version: str = Field(default="", max_length=128)
    agent_version: str = Field(default="", max_length=64)
    node_name: str = Field(default="", max_length=128)
    last_keepalive: str = Field(default="", max_length=64)
    group_config_status: str = Field(default="", max_length=64)


class AgentStatusSummary(StrictModel):
    active: int = Field(default=0, ge=0)
    disconnected: int = Field(default=0, ge=0)
    pending: int = Field(default=0, ge=0)
    never_connected: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


class ApiInfoObservation(StrictModel):
    title: str = Field(default="", max_length=64)
    api_version: str = Field(default="", max_length=32)
    revision: str = Field(default="", max_length=32)


class ManagerStatusObservation(StrictModel):
    daemons: dict[str, str] = Field(default_factory=dict)


class ManagerLogComponentSummary(StrictModel):
    component: str = Field(min_length=1, max_length=96)
    total: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    warning: int = Field(default=0, ge=0)
    error: int = Field(default=0, ge=0)
    critical: int = Field(default=0, ge=0)
    debug: int = Field(default=0, ge=0)


class AlertLevelCount(StrictModel):
    level: int = Field(ge=0, le=16)
    count: int = Field(ge=0)


class AlertSummary(StrictModel):
    total: int = Field(default=0, ge=0)
    window_minutes: int = Field(ge=1)
    minimum_rule_level: int = Field(ge=0, le=16)
    by_level: list[AlertLevelCount] = Field(default_factory=list)


class VulnerabilitySeverityCount(StrictModel):
    severity: str = Field(min_length=1, max_length=32)
    count: int = Field(ge=0)


class VulnerabilitySummary(StrictModel):
    total: int = Field(default=0, ge=0)
    by_severity: list[VulnerabilitySeverityCount] = Field(default_factory=list)
    max_cvss_base: float | None = Field(default=None, ge=0, le=10)
