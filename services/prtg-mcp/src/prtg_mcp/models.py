from __future__ import annotations

from typing import TypeAlias

from pydantic import Field

from mcp_common.operations import StrictModel

Scalar: TypeAlias = str | int | float | bool | None


class HealthStatusObservation(StrictModel):
    healthy: bool
    status_code: int = Field(ge=100, le=599)


class HealthMetric(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    value: Scalar


class DeviceObservation(StrictModel):
    object_id: int = Field(ge=0)
    probe: str = Field(max_length=512)
    group: str = Field(max_length=512)
    device: str = Field(max_length=512)
    status: str = Field(max_length=128)
    status_id: int | None = Field(default=None, ge=0, le=1000)
    message: str = Field(max_length=2048)
    priority: int | None = Field(default=None, ge=0, le=1000)
    dependency: str = Field(max_length=512)
    active: bool | None = None
    parent_id: int | None = Field(default=None, ge=0)
    sensor_counts: dict[str, int] = Field(default_factory=dict)


class SensorObservation(StrictModel):
    object_id: int = Field(ge=0)
    probe: str = Field(max_length=512)
    group: str = Field(max_length=512)
    device: str = Field(max_length=512)
    sensor: str = Field(max_length=512)
    sensor_type: str = Field(max_length=256)
    status: str = Field(max_length=128)
    status_id: int | None = Field(default=None, ge=0, le=1000)
    message: str = Field(max_length=2048)
    last_value: str = Field(max_length=1024)
    priority: int | None = Field(default=None, ge=0, le=1000)
    dependency: str = Field(max_length=512)
    active: bool | None = None
    parent_id: int | None = Field(default=None, ge=0)
    last_check: str = Field(max_length=128)
    interval: str = Field(max_length=128)


class ChannelObservation(StrictModel):
    object_id: int = Field(ge=0)
    name: str = Field(max_length=512)
    last_value: str = Field(max_length=1024)


class MessageObservation(StrictModel):
    object_id: int = Field(ge=0)
    datetime: str = Field(max_length=128)
    parent: str = Field(max_length=512)
    event_type: str = Field(max_length=256)
    name: str = Field(max_length=512)
    status: str = Field(max_length=128)
    message: str = Field(max_length=2048)
    priority: int | None = Field(default=None, ge=0, le=1000)


class HistoricSample(StrictModel):
    datetime: str = Field(max_length=128)
    values: dict[str, Scalar] = Field(default_factory=dict)
