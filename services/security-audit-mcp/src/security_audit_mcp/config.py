from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8090
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    security_audit_max_evidence: int = Field(default=200, ge=1, le=200)
    security_audit_budget_max_items: int = Field(default=400, ge=1, le=2_000)
    security_audit_budget_max_response_bytes: int = Field(
        default=2_097_152,
        ge=16_384,
        le=16_777_216,
    )
    security_audit_budget_timeout_seconds: float = Field(default=10.0, ge=0.5, le=60.0)
