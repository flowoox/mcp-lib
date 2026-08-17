from __future__ import annotations

from pydantic import BaseModel, Field


class RemoteFile(BaseModel):
    filename: str
    size: int = Field(default=0, ge=0)
    extension: str = ""
    bit_rate: int | None = None
    sample_rate: int | None = None
    bit_depth: int | None = None


class DownloadBatch(BaseModel):
    """One queued album: who serves it, which files, and where it belongs."""

    batch_id: str
    candidate_id: str
    username: str
    filenames: list[str]
    destination: str
    external_id: str = ""
    artist: str = ""
    album: str = ""
    queued_at: str = ""
    collected: bool = False
    # How often each file had to be asked for again. Peers drop single files
    # routinely; without this the whole album would count as lost.
    retries: dict[str, int] = Field(default_factory=dict)


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
