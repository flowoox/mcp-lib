from __future__ import annotations

from pydantic import BaseModel, Field


class ArchiveFile(BaseModel):
    """One file inside an Archive item, as the metadata API describes it."""

    name: str
    format: str = ""
    # "original" or "derivative". The Archive transcodes every upload, so the
    # same track appears two or three times and only the source tells them
    # apart.
    source: str = ""
    size: int = Field(default=0, ge=0)
    md5: str = ""
    extension: str = ""
    length_seconds: float | None = None
    track: int | None = None
    disc: int | None = None
    title: str = ""
    bit_rate: int | None = None


class AlbumCandidate(BaseModel):
    candidate_id: str
    search_id: str | None = None
    identifier: str
    folder: str
    artist: str
    album: str
    files: list[ArchiveFile]
    audio_file_count: int
    total_file_count: int
    disc_count: int = 1
    formats: list[str] = Field(default_factory=list)
    total_bytes: int = 0
    # Why this item may be copied at all. Carried on the candidate so the
    # operator sees the licence before authorizing, not after.
    license_url: str = ""
    license_label: str = ""
    rights_basis: str = ""
    collections: list[str] = Field(default_factory=list)
    detail_url: str = ""
    # The item's own artwork. Without it an album reaches the library with
    # no sleeve, and nothing downstream can invent one.
    cover_name: str = ""
    cover_size: int = 0
    score: float = 0
    score_reasons: list[str] = Field(default_factory=list)


class DownloadBatch(BaseModel):
    """One queued item: which files, where they go, and how far they got."""

    batch_id: str
    candidate_id: str
    identifier: str
    filenames: list[str]
    destination: str
    external_id: str = ""
    artist: str = ""
    album: str = ""
    license_url: str = ""
    license_label: str = ""
    cover_name: str = ""
    queued_at: str = ""
    state: str = "queued"
    collected: bool = False
    bytes_total: int = 0
    bytes_done: int = 0
    # Per remote file name, so a partially arrived album can say which track
    # is missing instead of only that something failed.
    file_states: dict[str, str] = Field(default_factory=dict)
    errors: dict[str, str] = Field(default_factory=dict)
    retries: dict[str, int] = Field(default_factory=dict)
    local_names: dict[str, str] = Field(default_factory=dict)
    # Kept from the candidate so a status poll can report progress without
    # re-fetching the item metadata on every call.
    file_sizes: dict[str, int] = Field(default_factory=dict)
