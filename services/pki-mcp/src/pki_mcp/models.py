from __future__ import annotations

from datetime import datetime

from mcp_common.operations import StrictModel
from pydantic import Field


class BackendEnvelope(StrictModel):
    items: list[dict] = Field(default_factory=list)
    nextCursor: str | None = None


class CAObservation(StrictModel):
    serviceState: str = Field(max_length=32)
    certificateNotBefore: datetime
    certificateNotAfter: datetime
    certificateDaysRemaining: int
    signatureAlgorithm: str = Field(max_length=128)
    crlPeriod: int | None = None
    crlPeriodUnits: str | None = Field(default=None, max_length=32)
    crlOverlapPeriod: int | None = None
    crlOverlapUnits: str | None = Field(default=None, max_length=32)


class RevocationPublicationObservation(StrictModel):
    crlPublicationTargetCount: int = Field(ge=0, le=256)
    caCertificatePublicationTargetCount: int = Field(ge=0, le=256)
    caCertificateCdpExtensionPresent: bool
    caCertificateAiaExtensionPresent: bool


class ExpiringCertificateObservation(StrictModel):
    requestId: int = Field(ge=1)
    template: str = Field(min_length=1, max_length=256)
    notBefore: datetime
    notAfter: datetime
    daysRemaining: int


class PKIEventObservation(StrictModel):
    eventId: int = Field(ge=0)
    level: str = Field(max_length=32)
    provider: str = Field(max_length=256)
    timeCreated: datetime
