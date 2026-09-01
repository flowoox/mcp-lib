from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8100, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    checkmk_api_base_url: str = ""
    checkmk_username: str = Field(default="", max_length=256)
    checkmk_automation_secret: SecretStr = SecretStr("")
    checkmk_backend_read_only: bool = False
    checkmk_backend_role: str = Field(default="", max_length=256)
    checkmk_allow_insecure_http: bool = False
    checkmk_tls_verify: bool = True

    checkmk_max_page_size: int = Field(default=100, ge=1, le=250)
    checkmk_max_sample_size: int = Field(default=50, ge=1, le=100)
    checkmk_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    checkmk_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    checkmk_max_concurrency: int = Field(default=2, ge=1, le=8)
    checkmk_rate_limit_per_second: float = Field(default=1.0, ge=0.05, le=20.0)
    checkmk_cache_max_age_seconds: int = Field(default=10, ge=0, le=300)

    checkmk_budget_max_requests: int = Field(default=6, ge=1, le=30)
    checkmk_budget_max_items: int = Field(default=300, ge=1, le=5_000)
    checkmk_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    checkmk_budget_max_fan_out: int = Field(default=4, ge=1, le=30)
    checkmk_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.checkmk_api_base_url.strip()
        if not value:
            return self
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("CHECKMK_API_BASE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "CHECKMK_API_BASE_URL must not contain credentials, query, or fragment"
            )
        normalized_path = parsed.path.rstrip("/")
        if not normalized_path.endswith("/check_mk/api/1.0"):
            raise ValueError(
                "CHECKMK_API_BASE_URL must end with the stable /check_mk/api/1.0 REST root"
            )
        if parsed.scheme == "http" and not self.checkmk_allow_insecure_http:
            raise ValueError("plain HTTP requires CHECKMK_ALLOW_INSECURE_HTTP=true")
        self.checkmk_api_base_url = urlunsplit(
            (parsed.scheme, parsed.netloc, normalized_path, "", "")
        )
        return self

    @property
    def configured(self) -> bool:
        return bool(
            self.checkmk_api_base_url
            and self.checkmk_username.strip()
            and self.checkmk_automation_secret.get_secret_value().strip()
            and self.checkmk_backend_role.strip()
        )
