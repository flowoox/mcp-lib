from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8096, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    freshdesk_api_base_url: str = ""
    freshdesk_api_key: SecretStr = SecretStr("")
    freshdesk_backend_read_only: bool = False
    freshdesk_allow_insecure_http: bool = False
    freshdesk_tls_verify: bool = True

    freshdesk_max_page_size: int = Field(default=100, ge=1, le=100)
    freshdesk_max_sample_size: int = Field(default=50, ge=1, le=100)
    freshdesk_max_page_number: int = Field(default=50, ge=1, le=300)
    freshdesk_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    freshdesk_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    freshdesk_max_concurrency: int = Field(default=2, ge=1, le=8)
    freshdesk_rate_limit_per_second: float = Field(default=0.5, ge=0.05, le=20.0)
    freshdesk_cache_max_age_seconds: int = Field(default=15, ge=0, le=300)

    freshdesk_budget_max_requests: int = Field(default=5, ge=1, le=30)
    freshdesk_budget_max_items: int = Field(default=250, ge=1, le=5_000)
    freshdesk_budget_max_response_bytes: int = Field(default=6_291_456, ge=16_384, le=33_554_432)
    freshdesk_budget_max_fan_out: int = Field(default=4, ge=1, le=30)
    freshdesk_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.freshdesk_api_base_url.strip()
        if not value:
            return self
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("FRESHDESK_API_BASE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "FRESHDESK_API_BASE_URL must not contain credentials, query, or fragment"
            )
        if parsed.path.rstrip("/"):
            raise ValueError(
                "FRESHDESK_API_BASE_URL must contain only the helpdesk origin, without an API path"
            )
        if parsed.scheme == "http" and not self.freshdesk_allow_insecure_http:
            raise ValueError("plain HTTP requires FRESHDESK_ALLOW_INSECURE_HTTP=true")
        self.freshdesk_api_base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        return self

    @property
    def configured(self) -> bool:
        return bool(
            self.freshdesk_api_base_url
            and self.freshdesk_api_key.get_secret_value().strip()
        )
