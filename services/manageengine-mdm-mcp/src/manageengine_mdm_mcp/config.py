from __future__ import annotations

import re
from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_CUSTOMER_ID_RE = re.compile(r"^[0-9]{1,32}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8095, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    mdm_api_base_url: str = ""
    mdm_auth_mode: Literal["cloud_oauth", "onprem_api_key"] = "cloud_oauth"
    mdm_api_token: SecretStr = SecretStr("")
    mdm_customer_id: str = ""
    mdm_backend_read_only: bool = False
    mdm_allow_insecure_http: bool = False
    mdm_tls_verify: bool = True

    mdm_max_page_size: int = Field(default=100, ge=1, le=250)
    mdm_max_sample_size: int = Field(default=50, ge=1, le=250)
    mdm_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    mdm_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    mdm_max_concurrency: int = Field(default=2, ge=1, le=8)
    mdm_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    mdm_cache_max_age_seconds: int = Field(default=15, ge=0, le=300)

    mdm_budget_max_requests: int = Field(default=6, ge=1, le=30)
    mdm_budget_max_items: int = Field(default=300, ge=1, le=5_000)
    mdm_budget_max_response_bytes: int = Field(default=6_291_456, ge=16_384, le=33_554_432)
    mdm_budget_max_fan_out: int = Field(default=6, ge=1, le=30)
    mdm_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @field_validator("mdm_customer_id")
    @classmethod
    def validate_customer_id(cls, value: str) -> str:
        normalized = value.strip()
        if normalized and not _CUSTOMER_ID_RE.fullmatch(normalized):
            raise ValueError("MDM_CUSTOMER_ID must contain 1-32 decimal digits")
        return normalized

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.mdm_api_base_url.strip()
        if not value:
            return self
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MDM_API_BASE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("MDM_API_BASE_URL must not contain credentials, query, or fragment")
        path = parsed.path.rstrip("/")
        if path:
            raise ValueError("MDM_API_BASE_URL must contain only the server origin, without an API path")
        if parsed.scheme == "http" and not self.mdm_allow_insecure_http:
            raise ValueError("plain HTTP requires MDM_ALLOW_INSECURE_HTTP=true")
        self.mdm_api_base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        return self

    @property
    def configured(self) -> bool:
        return bool(self.mdm_api_base_url and self.mdm_api_token.get_secret_value().strip())
