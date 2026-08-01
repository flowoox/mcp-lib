from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseMcpSettings(BaseSettings):
    """Settings shared by independently deployable MCP services."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    tz: str = "Europe/Zurich"
    downloads_dir: Path = Path("/downloads")
    log_level: str = "INFO"
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8080

    def ensure_directories(self) -> None:
        self.downloads_dir.mkdir(parents=True, exist_ok=True)


class SoulseekSettings(BaseMcpSettings):
    """Configuration owned only by the Soulseek MCP service."""

    state_db: Path = Path("/data/soulseek-mcp.sqlite3")
    mcp_port: int = 8081

    slskd_url: str = "http://slskd:5030"
    slskd_api_key: str = ""
    slskd_search_timeout: int = Field(default=15, ge=3, le=120)
    slskd_result_limit: int = Field(default=200, ge=1, le=1000)
    slskd_minimum_tracks: int = Field(default=4, ge=1, le=100)
    preferred_audio_formats: list[str] = Field(
        default_factory=lambda: [
            "flac",
            "wav",
            "alac",
            "aiff",
            "ape",
            "wv",
            "mp3",
            "m4a",
            "ogg",
            "opus",
        ]
    )

    @field_validator("preferred_audio_formats", mode="before")
    @classmethod
    def parse_string_list(cls, value: object) -> object:
        if isinstance(value, str):
            separator = "," if "," in value else " "
            return [part.strip().lower() for part in value.split(separator) if part.strip()]
        return value

    @field_validator("slskd_url", mode="after")
    @classmethod
    def strip_slskd_url(cls, value: str) -> str:
        return value.rstrip("/")

    def ensure_directories(self) -> None:
        super().ensure_directories()
        self.state_db.parent.mkdir(parents=True, exist_ok=True)


class TraxxSettings(BaseMcpSettings):
    """Configuration owned only by the Traxx/BeMusic MCP service."""

    mcp_port: int = 8082
    traxx_url: str = ""
    traxx_token: str = ""
    traxx_tus_endpoint: str = "/api/v1/tus/"
    traxx_verify_tls: bool = True
    traxx_upload_chunk_size: int = Field(default=8 * 1024 * 1024, ge=1024 * 1024)
    traxx_file_url_template: str = ""

    @field_validator("traxx_url", mode="after")
    @classmethod
    def strip_traxx_url(cls, value: str) -> str:
        return value.rstrip("/")


@lru_cache(maxsize=1)
def get_soulseek_settings() -> SoulseekSettings:
    settings = SoulseekSettings()
    settings.ensure_directories()
    return settings


@lru_cache(maxsize=1)
def get_traxx_settings() -> TraxxSettings:
    settings = TraxxSettings()
    settings.ensure_directories()
    return settings
