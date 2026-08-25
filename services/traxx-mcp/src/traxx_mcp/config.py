from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from mcp_common.store import AtomicJsonStore
from mcp_common.url_security import normalize_origin_url
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeConfig(BaseModel):
    base_url: str = ""
    token: str = ""
    # Sent with every request. Exists so a WAF or reverse proxy in front of the
    # instance can allow this client through without opening the API publicly.
    extra_headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    tus_endpoint: str = "/api/v1/tus/upload"
    upload_chunk_size: int = Field(default=8 * 1024 * 1024, ge=256 * 1024, le=64 * 1024 * 1024)
    file_url_template: str = ""
    timeout_seconds: int = Field(default=90, ge=10, le=900)

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        value = value.strip()
        return normalize_origin_url(value) if value else ""

    @field_validator("tus_endpoint")
    @classmethod
    def normalize_endpoint(cls, value: str) -> str:
        value = value.strip() or "/api/v1/tus/upload"
        return value if value.startswith("/") else f"/{value}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8082
    # Internal means network exposure is constrained by the deployment. Any
    # container/host/tenant-crossing endpoint must explicitly switch to
    # external, which fails closed unless MCP auth is configured.
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    traxx_config_file: Path = Path("/data/config.json")
    traxx_import_ledger_file: Path = Path("/data/imports.json")
    traxx_actors_file: Path = Path("/data/actors.json")
    downloads_dir: Path = Path("/downloads")

    # Deployment-owned malware gate. It is deliberately not persisted through
    # configure_traxx, so a web/API caller cannot turn it off at runtime.
    malware_scan_required: bool = False
    clamav_host: str = ""
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 180
    clamav_max_file_bytes: int = 1024 * 1024 * 1024
    clamav_max_files: int = 1000
    clamav_max_total_bytes: int = 8 * 1024 * 1024 * 1024
    malware_quarantine_dir: Path = Path("/downloads/.quarantine")

    traxx_url: str = ""
    traxx_token: str = ""
    traxx_extra_headers: dict[str, str] = {}
    traxx_verify_tls: bool = True
    # Explicit development escape hatch. Production defaults fail closed when
    # somebody tries to persist verify_tls=false through configure_traxx.
    traxx_allow_insecure_tls: bool = False
    # Comma-separated additional origins to which a configured connector may
    # be moved. The initial TRAXX_URL origin is always trusted automatically.
    traxx_allowed_origins: str = ""
    traxx_tus_endpoint: str = "/api/v1/tus/upload"
    traxx_upload_chunk_size: int = 8 * 1024 * 1024
    traxx_file_url_template: str = ""
    traxx_timeout_seconds: int = 90

    def initial_runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(
            base_url=self.traxx_url,
            token=self.traxx_token,
            extra_headers=dict(self.traxx_extra_headers),
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


class UnknownActorError(LookupError):
    """Raised when an actor_id has no registered token."""


class ActorRegistry:
    """File-backed map of actor_id -> bearer token for user-scoped requests.

    The orchestrator chooses opaque actor ids; this service only stores the
    matching token. The file lives next to the runtime config, is written
    atomically with owner-only permissions (see AtomicJsonStore), and tokens
    are never handed back through any tool output.
    """

    MAX_ID_LENGTH = 128

    def __init__(self, path: str | Path):
        self.store = AtomicJsonStore(path, default={})

    @classmethod
    def validate_actor_id(cls, actor_id: str) -> str:
        actor_id = actor_id.strip()
        if not actor_id or len(actor_id) > cls.MAX_ID_LENGTH or "\x00" in actor_id:
            raise ValueError(
                "actor_id must be a non-empty string of at most "
                f"{cls.MAX_ID_LENGTH} characters"
            )
        return actor_id

    def set(self, actor_id: str, token: str) -> str:
        actor_id = self.validate_actor_id(actor_id)
        if not token.strip():
            raise ValueError(f"A non-empty token is required for actor {actor_id!r}")
        self.store.update(**{actor_id: token.strip()})
        return actor_id

    def remove(self, actor_id: str) -> bool:
        actor_id = self.validate_actor_id(actor_id)
        actors = self.store.read()
        if actor_id not in actors:
            return False
        del actors[actor_id]
        self.store.write(actors)
        return True

    def list_ids(self) -> list[str]:
        return sorted(self.store.read())

    def has_tokens(self) -> bool:
        return bool(self.store.read())

    def token_for(self, actor_id: str) -> str:
        actor_id = self.validate_actor_id(actor_id)
        token = self.store.read().get(actor_id)
        if not isinstance(token, str) or not token:
            raise UnknownActorError(
                f"Unknown actor_id {actor_id!r}. Register it first with "
                "configure_traxx_actor."
            )
        return token


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.traxx_config_file.parent.mkdir(parents=True, exist_ok=True)
    settings.traxx_import_ledger_file.parent.mkdir(parents=True, exist_ok=True)
    settings.traxx_actors_file.parent.mkdir(parents=True, exist_ok=True)
    settings.downloads_dir.mkdir(parents=True, exist_ok=True)
    return settings
