from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _origin_only(value: str, *, field: str, allow_insecure_http: bool) -> str:
    normalized = value.strip()
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{field} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{field} must not contain credentials, query, or fragment")
    if parsed.path.rstrip("/"):
        raise ValueError(f"{field} must contain only the API origin, without a path")
    if parsed.scheme == "http" and not allow_insecure_http:
        raise ValueError(f"plain HTTP for {field} requires its allow-insecure setting")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8099, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    wazuh_server_api_base_url: str = ""
    wazuh_server_username: str = Field(default="", max_length=256)
    wazuh_server_password: SecretStr = SecretStr("")
    wazuh_server_backend_read_only: bool = False
    wazuh_server_backend_role: str = ""
    wazuh_server_allow_insecure_http: bool = False
    wazuh_server_tls_verify: bool = True

    wazuh_indexer_api_base_url: str = ""
    wazuh_indexer_username: str = Field(default="", max_length=256)
    wazuh_indexer_password: SecretStr = SecretStr("")
    wazuh_indexer_backend_read_only: bool = False
    wazuh_indexer_backend_role: str = ""
    wazuh_indexer_allow_insecure_http: bool = False
    wazuh_indexer_tls_verify: bool = True

    wazuh_max_page_size: int = Field(default=100, ge=1, le=500)
    wazuh_max_sample_size: int = Field(default=50, ge=1, le=100)
    wazuh_max_offset: int = Field(default=10_000, ge=100, le=100_000)
    wazuh_max_alert_window_minutes: int = Field(default=1_440, ge=15, le=10_080)
    wazuh_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    wazuh_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    wazuh_max_concurrency: int = Field(default=2, ge=1, le=8)
    wazuh_rate_limit_per_second: float = Field(default=1.0, ge=0.05, le=20.0)
    wazuh_cache_max_age_seconds: int = Field(default=15, ge=0, le=300)

    wazuh_budget_max_requests: int = Field(default=8, ge=1, le=30)
    wazuh_budget_max_items: int = Field(default=300, ge=1, le=5_000)
    wazuh_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    wazuh_budget_max_fan_out: int = Field(default=4, ge=1, le=30)
    wazuh_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def validate_endpoints(self) -> Self:
        self.wazuh_server_api_base_url = _origin_only(
            self.wazuh_server_api_base_url,
            field="WAZUH_SERVER_API_BASE_URL",
            allow_insecure_http=self.wazuh_server_allow_insecure_http,
        )
        self.wazuh_indexer_api_base_url = _origin_only(
            self.wazuh_indexer_api_base_url,
            field="WAZUH_INDEXER_API_BASE_URL",
            allow_insecure_http=self.wazuh_indexer_allow_insecure_http,
        )
        return self

    @property
    def server_configured(self) -> bool:
        return bool(
            self.wazuh_server_api_base_url
            and self.wazuh_server_username.strip()
            and self.wazuh_server_password.get_secret_value().strip()
        )

    @property
    def indexer_configured(self) -> bool:
        return bool(
            self.wazuh_indexer_api_base_url
            and self.wazuh_indexer_username.strip()
            and self.wazuh_indexer_password.get_secret_value().strip()
        )

    @property
    def server_read_only_attested(self) -> bool:
        return (
            self.wazuh_server_backend_read_only
            and self.wazuh_server_backend_role.strip().casefold() == "readonly"
        )

    @property
    def indexer_read_only_attested(self) -> bool:
        return (
            self.wazuh_indexer_backend_read_only
            and bool(self.wazuh_indexer_backend_role.strip())
        )
