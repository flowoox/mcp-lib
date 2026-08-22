from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime-only settings for the Windows-hosted AD MCP service."""

    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8084
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    ad_powershell_executable: str = "powershell.exe"
    ad_command_timeout_seconds: int = Field(default=30, ge=3, le=180)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
