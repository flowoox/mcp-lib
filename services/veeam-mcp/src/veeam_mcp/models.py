from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class JobStateObservation(StrictModel):
    job_id: str = Field(default="", max_length=36)
    name: str = Field(default="", max_length=256)
    job_type: str = Field(default="", max_length=64)
    status: str = Field(default="", max_length=64)
    last_run: str = Field(default="", max_length=64)
    last_result: str = Field(default="", max_length=64)
    next_run: str = Field(default="", max_length=64)
    objects_count: int | None = Field(default=None, ge=0)


class SessionObservation(StrictModel):
    session_id: str = Field(default="", max_length=36)
    job_id: str = Field(default="", max_length=36)
    name: str = Field(default="", max_length=256)
    session_type: str = Field(default="", max_length=96)
    state: str = Field(default="", max_length=64)
    result: str = Field(default="", max_length=64)
    progress_percent: int | None = Field(default=None, ge=0, le=100)
    creation_time: str = Field(default="", max_length=64)
    end_time: str = Field(default="", max_length=64)
    canceled: bool | None = None


class RepositoryStateObservation(StrictModel):
    repository_id: str = Field(default="", max_length=36)
    name: str = Field(default="", max_length=256)
    repository_type: str = Field(default="", max_length=64)
    capacity_gb: float | None = Field(default=None, ge=0)
    free_gb: float | None = Field(default=None, ge=0)
    used_space_gb: float | None = Field(default=None, ge=0)
    is_online: bool | None = None
    is_out_of_date: bool | None = None


class BackupObservation(StrictModel):
    backup_id: str = Field(default="", max_length=36)
    job_id: str = Field(default="", max_length=36)
    name: str = Field(default="", max_length=256)
    platform_name: str = Field(default="", max_length=64)
    job_type: str = Field(default="", max_length=64)
    creation_time: str = Field(default="", max_length=64)
    repository_id: str = Field(default="", max_length=36)


class RestorePointObservation(StrictModel):
    restore_point_id: str = Field(default="", max_length=36)
    backup_id: str = Field(default="", max_length=36)
    name: str = Field(default="", max_length=256)
    platform_name: str = Field(default="", max_length=64)
    restore_point_type: str = Field(default="", max_length=64)
    malware_status: str = Field(default="", max_length=64)
    creation_time: str = Field(default="", max_length=64)


class DiagnosticSummary(StrictModel):
    jobs_returned: int = Field(ge=0)
    jobs_failed_or_warning: int = Field(ge=0)
    repositories_returned: int = Field(ge=0)
    repositories_offline: int = Field(ge=0)
    repositories_out_of_date: int = Field(ge=0)
    sessions_returned: int = Field(ge=0)
    sessions_failed_or_warning: int = Field(ge=0)
    restore_points_returned: int = Field(ge=0)
    suspicious_or_infected_restore_points: int = Field(ge=0)
