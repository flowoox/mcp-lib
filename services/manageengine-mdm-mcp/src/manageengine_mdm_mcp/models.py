from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class DeviceObservation(StrictModel):
    device_id: str = Field(min_length=1, max_length=32)
    device_name: str = Field(default="", max_length=256)
    platform_type: str = Field(default="", max_length=32)
    platform_type_id: str = Field(default="", max_length=8)
    os_version: str = Field(default="", max_length=128)
    product_name: str = Field(default="", max_length=256)
    model: str = Field(default="", max_length=256)
    owned_by: str = Field(default="", max_length=32)
    lost_mode_enabled: bool | None = None
    profile_count: int | None = Field(default=None, ge=0)
    app_count: int | None = Field(default=None, ge=0)
    document_count: int | None = Field(default=None, ge=0)
    group_count: int | None = Field(default=None, ge=0)


class ScanStatusObservation(StrictModel):
    device_id: str = Field(min_length=1, max_length=32)
    status_code: int | None = None
    status_description: str = Field(default="", max_length=512)
    has_kb_url: bool = False


class CommandObservation(StrictModel):
    device_id: str = Field(min_length=1, max_length=32)
    command_history_id: str = Field(default="", max_length=32)
    command_name: str = Field(default="", max_length=256)
    command_status: int | None = None
    managed_status: int | None = None
    added_time: str = Field(default="", max_length=64)
    latest_status_code: int | None = None
    latest_status_description: str = Field(default="", max_length=512)
    latest_updated_time: str = Field(default="", max_length=64)


class CommandStatusSummary(StrictModel):
    total: int = Field(ge=0)
    by_status: dict[str, int] = Field(default_factory=dict)
