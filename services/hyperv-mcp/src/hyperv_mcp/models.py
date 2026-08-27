from __future__ import annotations

from datetime import datetime
from typing import Any

from mcp_common.operations import StrictModel
from pydantic import Field


class HyperVHostObservation(StrictModel):
    computerName: str = Field(min_length=1, max_length=255)
    available: bool
    vmCounts: dict[str, int] = Field(default_factory=dict, max_length=32)
    migrationEnabled: bool
    logicalProcessors: int = Field(ge=0, le=65_536)
    memoryCapacityBytes: int = Field(ge=0)
    memoryAssignedBytes: int = Field(ge=0)
    memoryAssignedPercent: float = Field(ge=0)


class VMObservation(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    state: str = Field(min_length=1, max_length=64)
    status: str = Field(max_length=512)
    generation: int = Field(ge=0, le=10)
    version: str = Field(max_length=64)
    uptimeSeconds: int = Field(ge=0)
    cpuUsagePercent: int = Field(ge=0)
    memoryAssignedBytes: int = Field(ge=0)
    memoryDemandBytes: int = Field(ge=0)
    processorCount: int = Field(ge=0, le=4_096)
    clustered: bool


class VMNetworkAdapterObservation(StrictModel):
    name: str = Field(max_length=256)
    switchName: str | None = Field(default=None, max_length=256)
    macAddress: str = Field(max_length=64)
    status: str = Field(max_length=128)
    ipAddresses: list[str] = Field(default_factory=list, max_length=32)


class VMIntegrationServiceObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    enabled: bool
    primaryStatus: str = Field(max_length=256)
    secondaryStatus: str = Field(max_length=256)


class VMDetailObservation(VMObservation):
    automaticStartAction: str = Field(max_length=64)
    automaticStopAction: str = Field(max_length=64)
    checkpointCount: int = Field(ge=0)
    networkAdapters: list[VMNetworkAdapterObservation] = Field(default_factory=list, max_length=64)
    integrationServices: list[VMIntegrationServiceObservation] = Field(
        default_factory=list, max_length=64
    )


class VMSwitchObservation(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    switchType: str = Field(max_length=64)
    netAdapterInterfaceDescription: str | None = Field(default=None, max_length=512)
    allowManagementOS: bool | None = None
    embeddedTeamingEnabled: bool | None = None
    iovEnabled: bool | None = None


class CheckpointObservation(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    vmName: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    snapshotType: str = Field(max_length=64)
    creationTime: datetime
    parentSnapshotName: str | None = Field(default=None, max_length=256)


class VHDObservation(StrictModel):
    vmName: str = Field(min_length=1, max_length=256)
    path: str = Field(min_length=1, max_length=2_048)
    controllerType: str = Field(max_length=64)
    controllerNumber: int = Field(ge=0)
    controllerLocation: int = Field(ge=0)
    vhdType: str | None = Field(default=None, max_length=64)
    vhdFormat: str | None = Field(default=None, max_length=64)
    sizeBytes: int | None = Field(default=None, ge=0)
    fileSizeBytes: int | None = Field(default=None, ge=0)


class ReplicationObservation(StrictModel):
    vmName: str = Field(min_length=1, max_length=256)
    state: str = Field(max_length=128)
    health: str = Field(max_length=128)
    mode: str = Field(max_length=128)
    primaryServer: str = Field(max_length=512)
    replicaServer: str = Field(max_length=512)
    lastReplicationTime: datetime | None = None
    frequencySeconds: int | None = Field(default=None, ge=0)


class HyperVEventObservation(StrictModel):
    recordId: int = Field(ge=0)
    eventId: int = Field(ge=0)
    level: str = Field(max_length=64)
    providerName: str = Field(min_length=1, max_length=512)
    timeCreated: datetime | None = None
    messagePreview: str | None = Field(default=None, max_length=512)


class BackendEnvelope(StrictModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    nextCursor: str | None = Field(default=None, min_length=1, max_length=32)
