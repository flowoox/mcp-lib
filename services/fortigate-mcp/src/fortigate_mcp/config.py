from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8086
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    fortigate_base_url: str = ""
    fortigate_api_token: SecretStr = SecretStr("")
    fortigate_vdom: str = "root"
    fortigate_ca_bundle: str = ""
    fortigate_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    fortigate_max_response_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=4096,
        le=16 * 1024 * 1024,
    )
    fortigate_max_items: int = Field(default=500, ge=1, le=2000)

    @field_validator("fortigate_vdom")
    @classmethod
    def validate_vdom(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("FORTIGATE_VDOM must not be blank")
        if len(value) > 79:
            raise ValueError("FORTIGATE_VDOM must not exceed 79 characters")
        if any(ord(character) < 32 for character in value):
            raise ValueError("FORTIGATE_VDOM must not contain control characters")
        return value

    @property
    def fortigate_configured(self) -> bool:
        return bool(
            self.fortigate_base_url.strip()
            and self.fortigate_api_token.get_secret_value().strip()
        )
