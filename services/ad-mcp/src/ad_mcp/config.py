from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
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
    ad_write_mode: Literal["disabled", "approval_hmac"] = "disabled"
    ad_approval_hmac_key: SecretStr = SecretStr("")
    ad_plan_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    ad_operation_store_file: str = "C:/ProgramData/flowoox/mcp-ad/operations.json"

    @model_validator(mode="after")
    def validate_write_boundary(self) -> Settings:
        if self.ad_write_mode == "approval_hmac":
            if len(self.ad_approval_hmac_key.get_secret_value()) < 32:
                raise ValueError(
                    "AD_APPROVAL_HMAC_KEY must be at least 32 characters when writes are enabled"
                )
            if not self.ad_operation_store_file.strip():
                raise ValueError("AD_OPERATION_STORE_FILE must not be blank when writes are enabled")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
