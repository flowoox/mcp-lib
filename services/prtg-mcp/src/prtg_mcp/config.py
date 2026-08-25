from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8090, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    prtg_base_url: str = ""
    prtg_api_key: SecretStr = SecretStr("")
    prtg_backend_read_only: bool = False
    prtg_allow_insecure_http: bool = False
    prtg_tls_verify: bool = True

    prtg_max_page_size: int = Field(default=100, ge=1, le=500)
    prtg_max_sample_size: int = Field(default=50, ge=1, le=500)
    prtg_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    prtg_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    prtg_max_concurrency: int = Field(default=2, ge=1, le=8)
    prtg_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    prtg_cache_max_age_seconds: int = Field(default=15, ge=0, le=300)
    prtg_health_max_age_seconds: int = Field(default=120, ge=30, le=900)
    prtg_historic_max_window_hours: int = Field(default=24, ge=1, le=960)

    prtg_budget_max_requests: int = Field(default=8, ge=1, le=30)
    prtg_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    prtg_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    prtg_budget_max_fan_out: int = Field(default=8, ge=1, le=30)
    prtg_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.prtg_base_url.strip()
        if not value:
            return self
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("PRTG_BASE_URL must be an absolute HTTP(S) origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("PRTG_BASE_URL must not contain credentials, query, or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("PRTG_BASE_URL must be an origin without an application path")
        if parsed.scheme == "http" and not self.prtg_allow_insecure_http:
            raise ValueError("plain HTTP requires PRTG_ALLOW_INSECURE_HTTP=true")
        self.prtg_base_url = value.rstrip("/")
        return self

    @property
    def configured(self) -> bool:
        return bool(self.prtg_base_url and self.prtg_api_key.get_secret_value().strip())
