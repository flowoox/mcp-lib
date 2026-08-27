from __future__ import annotations

from datetime import datetime
from typing import Any

from mcp_common.operations import StrictModel
from pydantic import Field


class ClusterObservation(StrictModel):
    clusterName: str = Field(min_length=1, max_length=256)
    available: bool
    nodeCounts: dict[str, int] = Field(default_factory=dict, max_length=32)
    groupCounts: dict[str, int] = Field(default_factory=dict, max_length=32)
    resourceCounts: dict[str, int] = Field(default_factory=dict, max_length=32)
    sharedVolumeCount: int = Field(ge=0)
    quorumType: str = Field(max_length=128)
    quorumResource: str | None = Field(default=None, max_length=256)
    dynamicQuorum: int | None = None


class ClusterNodeObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    state: str = Field(max_length=64)
    nodeWeight: int | None = None
    dynamicWeight: int | None = None
    drainStatus: str | None = Field(default=None, max_length=128)


class ClusterGroupObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    state: str = Field(max_length=64)
    ownerNode: str | None = Field(default=None, max_length=256)
    isCoreGroup: bool
    failoverPeriodHours: int | None = Field(default=None, ge=0)
    failoverThreshold: int | None = Field(default=None, ge=0)


class ClusterResourceObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    resourceType: str = Field(max_length=256)
    state: str = Field(max_length=64)
    ownerGroup: str | None = Field(default=None, max_length=256)
    ownerNode: str | None = Field(default=None, max_length=256)
    isCoreResource: bool
    persistentState: int | None = None
    restartAction: int | None = None


class ClusterGroupDetailObservation(ClusterGroupObservation):
    resources: list[ClusterResourceObservation] = Field(default_factory=list, max_length=256)
    resourceCount: int = Field(ge=0)
    resourcesTruncated: bool


class ClusterNetworkObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    state: str = Field(max_length=64)
    role: str = Field(max_length=128)
    address: str = Field(max_length=128)
    addressMask: str = Field(max_length=128)
    metric: int | None = Field(default=None, ge=0)
    autoMetric: bool | None = None


class ClusterStorageObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    state: str = Field(max_length=64)
    ownerNode: str | None = Field(default=None, max_length=256)
    volumePath: str | None = Field(default=None, max_length=2_048)
    totalBytes: int | None = Field(default=None, ge=0)
    freeBytes: int | None = Field(default=None, ge=0)
    percentFree: float | None = Field(default=None, ge=0, le=100)


class ClusterQuorumObservation(StrictModel):
    clusterName: str = Field(min_length=1, max_length=256)
    quorumType: str = Field(max_length=128)
    quorumResource: str | None = Field(default=None, max_length=256)
    witnessType: str | None = Field(default=None, max_length=256)


class ClusterEventObservation(StrictModel):
    recordId: int = Field(ge=0)
    eventId: int = Field(ge=0)
    level: str = Field(max_length=64)
    providerName: str = Field(min_length=1, max_length=512)
    timeCreated: datetime | None = None
    messagePreview: str | None = Field(default=None, max_length=512)


class BackendEnvelope(StrictModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    nextCursor: str | None = Field(default=None, min_length=1, max_length=32)
