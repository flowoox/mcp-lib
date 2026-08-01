from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    tz: str = "Europe/Berlin"
    app_secret: str = "development-only-change-me"
    state_db: Path = Path("/data/mcp-lib.sqlite3")
    downloads_dir: Path = Path("/downloads")
    log_level: str = "INFO"

    control_host: str = "0.0.0.0"
    control_port: int = 8080
    dashboard_username: str | None = None
    dashboard_password: str | None = None
    schedule_enabled: bool = True
    schedule_hour: int = Field(default=3, ge=0, le=23)
    schedule_minute: int = Field(default=0, ge=0, le=59)
    discovery_albums_per_day: int = Field(default=5, ge=1, le=50)
    poll_interval_seconds: int = Field(default=60, ge=15, le=3600)

    spotify_client_id: str = ""
    spotify_redirect_uri: str = "http://127.0.0.1:8080/spotify/callback"
    spotify_scopes: list[str] = Field(
        default_factory=lambda: [
            "user-top-read",
            "user-read-private",
            "user-read-email",
            "user-library-read",
        ]
    )

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

    traxx_url: str = ""
    traxx_token: str = ""
    traxx_tus_endpoint: str = "/api/v1/tus/"
    traxx_verify_tls: bool = True
    traxx_upload_chunk_size: int = Field(default=8 * 1024 * 1024, ge=1024 * 1024)
    traxx_file_url_template: str = ""

    auto_download: bool = False
    auto_import: bool = False
    authorized_library: bool = False
    default_rights_basis: str = ""
    default_rights_reference: str = ""

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8081

    @field_validator("spotify_scopes", "preferred_audio_formats", mode="before")
    @classmethod
    def parse_string_list(cls, value: object) -> object:
        if isinstance(value, str):
            separator = "," if "," in value else " "
            return [part.strip().lower() for part in value.split(separator) if part.strip()]
        return value

    @field_validator("slskd_url", "traxx_url", mode="after")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    def ensure_directories(self) -> None:
        self.state_db.parent.mkdir(parents=True, exist_ok=True)
        self.downloads_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings
