from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def normalize_prtg_base_url(value: str, *, allow_http: bool) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("PRTG_BASE_URL must be configured")
    if any(ord(character) < 32 for character in raw):
        raise ValueError("PRTG_BASE_URL must not contain control characters")
    parsed = urlsplit(raw)
    if parsed.username or parsed.password:
        raise ValueError("PRTG_BASE_URL must not contain URL userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("PRTG_BASE_URL must not contain a query or fragment")
    if parsed.scheme not in {"https", "http"}:
        raise ValueError("PRTG_BASE_URL must use https://")
    if parsed.scheme == "http" and not allow_http:
        raise ValueError("HTTP PRTG backends require PRTG_ALLOW_INSECURE_HTTP=true")
    if not parsed.hostname or parsed.path not in {"", "/"}:
        raise ValueError("PRTG_BASE_URL must be a bare origin without an application path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("PRTG_BASE_URL contains an invalid port") from exc
    return raw.rstrip("/")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8087
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    prtg_base_url: str = ""
    prtg_api_key: SecretStr = SecretStr("")
    prtg_backend_read_only: bool = False
    prtg_tls_verify: bool = True
    prtg_allow_insecure_tls: bool = False
    prtg_allow_insecure_http: bool = False
    prtg_timezone: str = "UTC"

    prtg_max_page_size: int = Field(default=100, ge=1, le=500)
    prtg_max_sample_size: int = Field(default=50, ge=1, le=500)
    prtg_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=30.0)
    prtg_max_response_bytes: int = Field(default=1_048_576, ge=16_384, le=8_388_608)
    prtg_max_concurrency: int = Field(default=2, ge=1, le=8)
    prtg_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    prtg_cache_max_age_seconds: int = Field(default=10, ge=0, le=300)

    prtg_historic_max_window_minutes: int = Field(default=10_080, ge=15, le=57_600)
    prtg_historic_min_average_minutes: int = Field(default=15, ge=1, le=1_440)
    prtg_historic_rate_limit_per_minute: int = Field(default=5, ge=1, le=5)
    prtg_historic_max_rows: int = Field(default=500, ge=1, le=2_000)
    prtg_historic_max_columns: int = Field(default=16, ge=1, le=64)

    prtg_budget_max_requests: int = Field(default=4, ge=1, le=20)
    prtg_budget_max_items: int = Field(default=300, ge=1, le=2_000)
    prtg_budget_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    prtg_budget_max_fan_out: int = Field(default=4, ge=1, le=20)
    prtg_budget_timeout_seconds: float = Field(default=30.0, ge=2.0, le=120.0)

    @field_validator("prtg_timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 100:
            raise ValueError("PRTG_TIMEZONE must contain 1-100 characters")
        try:
            ZoneInfo(normalized)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("PRTG_TIMEZONE must be a valid IANA timezone") from exc
        return normalized
