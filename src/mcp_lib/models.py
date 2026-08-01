from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RemoteFile(BaseModel):
    filename: str
    size: int = 0
    extension: str = ""
    bit_rate: int | None = None
    sample_rate: int | None = None
    bit_depth: int | None = None


class AlbumCandidate(BaseModel):
    candidate_id: str
    search_id: str | None = None
    username: str
    folder: str
    artist: str
    album: str
    files: list[RemoteFile]
    audio_file_count: int
    total_file_count: int
    disc_count: int = 1
    formats: list[str] = Field(default_factory=list)
    total_bytes: int = 0
    free_upload_slots: bool | None = None
    upload_speed: int | None = None
    queue_length: int | None = None
    score: float = 0
    score_reasons: list[str] = Field(default_factory=list)


RightsBasis = Literal[
    "owned-copy",
    "licensed",
    "public-domain",
    "artist-permission",
    "other-documented-permission",
]


class RightsAssertion(BaseModel):
    confirmed: bool
    basis: RightsBasis
    reference: str = ""
