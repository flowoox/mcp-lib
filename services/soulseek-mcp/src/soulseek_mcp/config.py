from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from mcp_common.store import AtomicJsonStore
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeConfig(BaseModel):
    base_url: str = "http://slskd:5030"
    api_key: str = ""
    search_timeout: int = Field(default=20, ge=3, le=180)
    result_limit: int = Field(default=300, ge=1, le=2000)
    minimum_tracks: int = Field(default=4, ge=1, le=150)
    preferred_formats: list[str] = Field(
        default_factory=lambda: ["flac", "wav", "alac", "aiff", "aif", "ape", "wv"]
    )
    lossless_only: bool = True
    minimum_lossy_bitrate_kbps: int = Field(default=320, ge=128, le=1411)
    auto_reconnect: bool = True
    reconnect_wait_seconds: int = Field(default=12, ge=1, le=60)
    reconnect_cooldown_seconds: int = Field(default=30, ge=1, le=300)
    minimum_free_space_gib: int = Field(default=20, ge=0, le=1024)
    minimum_free_space_percent: int = Field(default=20, ge=0, le=95)

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return value.strip().rstrip("/")

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
    mcp_port: int = 8081
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    soulseek_config_file: Path = Path("/data/config.json")
    soulseek_candidate_file: Path = Path("/data/candidates.json")
    soulseek_batch_file: Path = Path("/data/batches.json")
    downloads_dir: Path = Path("/downloads")
    slskd_config_path: Path = Path("/slskd/slskd.yml")

    slskd_url: str = "http://slskd:5030"
    slskd_api_key: str = ""
    slskd_search_timeout: int = 20
    slskd_result_limit: int = 300
    slskd_minimum_tracks: int = 4
    preferred_audio_formats: str = "flac,wav,alac,aiff,aif,ape,wv"
    lossless_only: bool = True
    minimum_lossy_bitrate_kbps: int = 320
    slskd_auto_reconnect: bool = True
    slskd_reconnect_wait_seconds: int = 12
    slskd_reconnect_cooldown_seconds: int = 30
    slskd_minimum_free_space_gib: int = 20
    slskd_minimum_free_space_percent: int = 20

    def initial_runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(
            base_url=self.slskd_url,
            api_key=self.slskd_api_key,
            search_timeout=self.slskd_search_timeout,
            result_limit=self.slskd_result_limit,
            minimum_tracks=self.slskd_minimum_tracks,
            preferred_formats=self.preferred_audio_formats,
            lossless_only=self.lossless_only,
            minimum_lossy_bitrate_kbps=self.minimum_lossy_bitrate_kbps,
            auto_reconnect=self.slskd_auto_reconnect,
            reconnect_wait_seconds=self.slskd_reconnect_wait_seconds,
            reconnect_cooldown_seconds=self.slskd_reconnect_cooldown_seconds,
            minimum_free_space_gib=self.slskd_minimum_free_space_gib,
            minimum_free_space_percent=self.slskd_minimum_free_space_percent,
        )


class RuntimeConfigStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        initial = settings.initial_runtime_config().model_dump(mode="json")
        self.store = AtomicJsonStore(settings.soulseek_config_file, default=initial)
        if not settings.soulseek_config_file.exists():
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
    settings.soulseek_config_file.parent.mkdir(parents=True, exist_ok=True)
    settings.soulseek_candidate_file.parent.mkdir(parents=True, exist_ok=True)
    settings.soulseek_batch_file.parent.mkdir(parents=True, exist_ok=True)
    settings.downloads_dir.mkdir(parents=True, exist_ok=True)
    settings.slskd_config_path.parent.mkdir(parents=True, exist_ok=True)
    return settings
