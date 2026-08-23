from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from mcp_common.operations import StrictModel


class HostObservation(StrictModel):
    computerName: str = Field(min_length=1, max_length=255)
    osCaption: str = Field(min_length=1, max_length=500)
    osVersion: str = Field(min_length=1, max_length=100)
    buildNumber: str = Field(min_length=1, max_length=100)
    lastBootTime: datetime
    uptimeSeconds: int = Field(ge=0)
    totalMemoryBytes: int = Field(ge=0)
    logicalProcessors: int = Field(ge=1, le=65_536)
    domainRole: int = Field(ge=0, le=5)
    rebootPending: bool


class ServiceObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    displayName: str = Field(min_length=1, max_length=512)
    status: str = Field(min_length=1, max_length=64)
    startType: str = Field(min_length=1, max_length=64)


class ProcessObservation(StrictModel):
    processName: str = Field(min_length=1, max_length=256)
    processId: int = Field(ge=0)
    cpuSeconds: float | None = Field(default=None, ge=0)
    workingSetBytes: int = Field(ge=0)


class FeatureObservation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    displayName: str = Field(min_length=1, max_length=512)
    installed: bool
    installState: str = Field(min_length=1, max_length=64)
    restartNeeded: str = Field(min_length=1, max_length=64)


class EventObservation(StrictModel):
    recordId: int = Field(ge=0)
    eventId: int = Field(ge=0)
    level: str = Field(min_length=0, max_length=64)
    providerName: str = Field(min_length=1, max_length=512)
    timeCreated: datetime | None
    messagePreview: str | None = Field(default=None, max_length=512)


class CertificateObservation(StrictModel):
    thumbprint: str = Field(min_length=1, max_length=256)
    subject: str = Field(max_length=2_048)
    issuer: str = Field(max_length=2_048)
    notBefore: datetime
    notAfter: datetime
    hasPrivateKey: bool


class UpdateObservation(StrictModel):
    hotFixId: str = Field(min_length=1, max_length=128)
    description: str = Field(max_length=512)
    installedOn: datetime | None


class HyperVHostObservation(StrictModel):
    available: bool
    vmCounts: dict[str, int] = Field(default_factory=dict, max_length=32)
    migrationEnabled: bool


class BackendEnvelope(StrictModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    nextCursor: str | None = Field(default=None, min_length=1, max_length=32)
