from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class ApplicationObservation(StrictModel):
    application_version: str = Field(min_length=1, max_length=64)


class SiteObservation(StrictModel):
    site_id: str = Field(min_length=36, max_length=36)
    name: str = Field(default="", max_length=256)


class DeviceObservation(StrictModel):
    device_id: str = Field(min_length=36, max_length=36)
    name: str = Field(default="", max_length=256)
    model: str = Field(default="", max_length=128)
    state: str = Field(default="", max_length=64)
    supported: bool | None = None
    firmware_version: str = Field(default="", max_length=128)
    firmware_updatable: bool | None = None
    features: list[str] = Field(default_factory=list, max_length=16)
    interfaces: list[str] = Field(default_factory=list, max_length=16)
    adopted_at: str = Field(default="", max_length=64)
    provisioned_at: str = Field(default="", max_length=64)
    has_uplink: bool = False
    port_count: int = Field(default=0, ge=0, le=10_000)
    radio_count: int = Field(default=0, ge=0, le=1_000)


class RadioStatistics(StrictModel):
    frequency_ghz: str = Field(default="", max_length=16)
    tx_retries_pct: float | None = None


class DeviceStatisticsObservation(StrictModel):
    uptime_seconds: int | None = Field(default=None, ge=0)
    last_heartbeat_at: str = Field(default="", max_length=64)
    next_heartbeat_at: str = Field(default="", max_length=64)
    load_average_1m: float | None = None
    load_average_5m: float | None = None
    load_average_15m: float | None = None
    cpu_utilization_pct: float | None = None
    memory_utilization_pct: float | None = None
    uplink_tx_rate_bps: int | None = Field(default=None, ge=0)
    uplink_rx_rate_bps: int | None = Field(default=None, ge=0)
    radios: list[RadioStatistics] = Field(default_factory=list, max_length=32)


class ClientObservation(StrictModel):
    client_id: str = Field(min_length=36, max_length=36)
    client_type: str = Field(default="", max_length=64)
    connected_at: str = Field(default="", max_length=64)
    access_type: str = Field(default="", max_length=64)
    access_authorized: bool | None = None


class SiteDiagnosticSummary(StrictModel):
    devices_returned: int = Field(ge=0)
    devices_online: int = Field(ge=0)
    devices_offline_or_degraded: int = Field(ge=0)
    devices_firmware_updatable: int = Field(ge=0)
    clients_returned: int = Field(ge=0)
    client_types: dict[str, int] = Field(default_factory=dict)
