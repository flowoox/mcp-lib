from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from mcp_common.store import AtomicJsonStore
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeConfig(BaseModel):
    base_url: str = "https://archive.org"
    # The Archive asks callers to identify themselves; a contact address makes
    # a blocked client reachable instead of anonymous.
    user_agent: str = "flowoox-mcp-archive/0.1 (+https://github.com/flowoox/mcp-lib)"
    search_timeout: int = Field(default=30, ge=3, le=180)
    result_limit: int = Field(default=40, ge=1, le=200)
    # How many items are opened for their file list per search. Every one is a
    # separate metadata request, so this bounds the cost of a wide query.
    metadata_probe_limit: int = Field(default=12, ge=1, le=60)
    minimum_tracks: int = Field(default=1, ge=1, le=150)
    preferred_formats: list[str] = Field(
        default_factory=lambda: ["flac", "wav", "aiff", "aif", "mp3", "ogg", "m4a"]
    )
    lossless_only: bool = False
    minimum_lossy_bitrate_kbps: int = Field(default=128, ge=32, le=1411)
    max_parallel_downloads: int = Field(default=3, ge=1, le=8)
    download_timeout_seconds: int = Field(default=900, ge=30, le=7200)

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return (value or "").strip().rstrip("/") or "https://archive.org"

    @field_validator("preferred_formats", mode="before")
    @classmethod
    def parse_formats(cls, value: object) -> object:
        if isinstance(value, str):
            return [
                part.strip().casefold()
                for part in value.replace(" ", ",").split(",")
                if part.strip()
            ]
        return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8083
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    archive_config_file: Path = Path("/data/config.json")
    archive_candidate_file: Path = Path("/data/candidates.json")
    archive_batch_file: Path = Path("/data/batches.json")
    downloads_dir: Path = Path("/downloads")

    archive_url: str = "https://archive.org"
    archive_user_agent: str = (
        "flowoox-mcp-archive/0.1 (+https://github.com/flowoox/mcp-lib)"
    )
    archive_search_timeout: int = 30
    archive_result_limit: int = 40
    archive_metadata_probe_limit: int = 12
    archive_minimum_tracks: int = 1
    preferred_audio_formats: str = "flac,wav,aiff,aif,mp3,ogg,m4a"
    lossless_only: bool = False
    minimum_lossy_bitrate_kbps: int = 128
    archive_max_parallel_downloads: int = 3
    archive_download_timeout_seconds: int = 900

    def initial_runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(
            base_url=self.archive_url,
            user_agent=self.archive_user_agent,
            search_timeout=self.archive_search_timeout,
            result_limit=self.archive_result_limit,
            metadata_probe_limit=self.archive_metadata_probe_limit,
            minimum_tracks=self.archive_minimum_tracks,
            preferred_formats=self.preferred_audio_formats,
            lossless_only=self.lossless_only,
            minimum_lossy_bitrate_kbps=self.minimum_lossy_bitrate_kbps,
            max_parallel_downloads=self.archive_max_parallel_downloads,
            download_timeout_seconds=self.archive_download_timeout_seconds,
        )


class RuntimeConfigStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        initial = settings.initial_runtime_config().model_dump(mode="json")
        self.store = AtomicJsonStore(settings.archive_config_file, default=initial)
        if not settings.archive_config_file.exists():
            self.store.write(initial)

    def get(self) -> RuntimeConfig:
        raw = self.store.read()
        merged = self.settings.initial_runtime_config().model_dump(mode="json")
        merged.update(raw)
        return RuntimeConfig.model_validate(merged)

    def save(self, config: RuntimeConfig) -> RuntimeConfig:
        self.store.write(config.model_dump(mode="json"))
        return config


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.archive_config_file.parent.mkdir(parents=True, exist_ok=True)
    settings.archive_candidate_file.parent.mkdir(parents=True, exist_ok=True)
    settings.archive_batch_file.parent.mkdir(parents=True, exist_ok=True)
    settings.downloads_dir.mkdir(parents=True, exist_ok=True)
    return settings
