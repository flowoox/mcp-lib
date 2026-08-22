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
    ad_writes_enabled: bool = False
    ad_approval_secret: str = ""

    def validate_write_boundary(self) -> None:
        """Fail closed when mutation support is enabled without an approval verifier."""
        if self.ad_writes_enabled and len(self.ad_approval_secret.encode("utf-8")) < 32:
            raise ValueError(
                "AD_WRITES_ENABLED requires AD_APPROVAL_SECRET with at least 32 bytes"
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_write_boundary()
    return settings
