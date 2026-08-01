from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

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


class SpotifyAlbumCandidate(BaseModel):
    spotify_id: str
    name: str
    artists: list[dict[str, Any]]
    release_date: str = ""
    album_type: str = "album"
    total_tracks: int = 0
    image_url: str = ""
    spotify_url: str = ""
    source_reasons: list[str] = Field(default_factory=list)
    score: float = 0

    @property
    def primary_artist(self) -> str:
        if not self.artists:
            return "Unknown Artist"
        return str(self.artists[0].get("name") or "Unknown Artist")

    @property
    def album_key(self) -> str:
        return f"{self.primary_artist.casefold()}::{self.name.casefold()}"


class Recommendation(BaseModel):
    id: str
    profile_id: str
    spotify_album_id: str
    artist: str
    album: str
    release_date: str = ""
    image_url: str = ""
    spotify_url: str = ""
    score: float = 0
    source_reasons: list[str] = Field(default_factory=list)
    status: str = "recommended"
    candidate_id: str | None = None
    slskd_batch_id: str | None = None
    local_path: str | None = None
    rights_basis: str = ""
    rights_reference: str = ""
    traxx_result: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ConnectorHealth(BaseModel):
    name: str
    ok: bool
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)
