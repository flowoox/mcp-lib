from __future__ import annotations

from functools import cached_property
from typing import Literal, Self

from pydantic import Field, TypeAdapter, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import ShareRoot


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8091, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    fileshare_roots_json: str = "[]"
    fileshare_backend_read_only: bool = False
    fileshare_powershell_executable: Literal["powershell.exe", "pwsh.exe"] = "powershell.exe"
    fileshare_allow_reparse_points: bool = False
    fileshare_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    fileshare_max_response_bytes: int = Field(default=1_048_576, ge=16_384, le=16_777_216)
    fileshare_max_page_size: int = Field(default=100, ge=1, le=500)

    fileshare_budget_max_requests: int = Field(default=6, ge=1, le=30)
    fileshare_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    fileshare_budget_max_response_bytes: int = Field(default=4_194_304, ge=16_384, le=33_554_432)
    fileshare_budget_max_fan_out: int = Field(default=6, ge=1, le=30)
    fileshare_budget_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)

    @cached_property
    def roots(self) -> tuple[ShareRoot, ...]:
        try:
            roots = TypeAdapter(list[ShareRoot]).validate_json(self.fileshare_roots_json)
        except ValueError as exc:
            raise ValueError("FILESHARE_ROOTS_JSON must be a JSON array of root objects") from exc
        aliases = [root.alias for root in roots]
        if len(aliases) != len(set(aliases)):
            raise ValueError("FILESHARE_ROOTS_JSON aliases must be unique")
        return tuple(roots)

    @model_validator(mode="after")
    def validate_backend_attestation(self) -> Self:
        if self.fileshare_backend_read_only and not self.roots:
            raise ValueError("read-only backend attestation requires at least one configured root")
        return self
