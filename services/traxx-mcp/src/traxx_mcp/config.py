from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from mcp_common.store import AtomicJsonStore
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    verify_tls: bool = True
    tus_endpoint: str = "/api/v1/tus/"
    upload_chunk_size: int = Field(default=8 * 1024 * 1024, ge=256 * 1024, le=64 * 1024 * 1024)
    file_url_template: str = ""
    timeout_seconds: int = Field(default=90, ge=10, le=900)

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return value.strip().rstrip("/")

    @field_validator("tus_endpoint")
    @classmethod
    def normalize_endpoint(cls, value: str) -> str:
        value = value.strip() or "/api/v1/tus/"
        return value if value.startswith("/") else f"/{value}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8082
    traxx_config_file: Path = Path("/data/config.json")
    traxx_import_ledger_file: Path = Path("/data/imports.json")
    downloads_dir: Path = Path("/downloads")

    traxx_url: str = ""
    traxx_token: str = ""
    traxx_verify_tls: bool = True
    traxx_tus_endpoint: str = "/api/v1/tus/"
    traxx_upload_chunk_size: int = 8 * 1024 * 1024
    traxx_file_url_template: str = ""
    traxx_timeout_seconds: int = 90

    def initial_runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(
            base_url=self.traxx_url,
            token=self.traxx_token,
            verify_tls=self.traxx_verify_tls,
            tus_endpoint=self.traxx_tus_endpoint,
            upload_chunk_size=self.traxx_upload_chunk_size,
            file_url_template=self.traxx_file_url_template,
            timeout_seconds=self.traxx_timeout_seconds,
        )


class RuntimeConfigStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        initial = settings.initial_runtime_config().model_dump(mode="json")
        self.store = AtomicJsonStore(settings.traxx_config_file, default=initial)
        if not settings.traxx_config_file.exists():
            self.store.write(initial)

    def get(self) -> RuntimeConfig:
        merged = self.settings.initial_runtime_config().model_dump(mode="json")
        merged.update(self.store.read())
        return RuntimeConfig.model_validate(merged)

    def save(self, config: RuntimeConfig) -> RuntimeConfig:
        self.store.write(config.model_dump(mode="json"))
        return config


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.traxx_config_file.parent.mkdir(parents=True, exist_ok=True)
    settings.traxx_import_ledger_file.parent.mkdir(parents=True, exist_ok=True)
    settings.downloads_dir.mkdir(parents=True, exist_ok=True)
    return settings
