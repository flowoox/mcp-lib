from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MINIMUM_SECURE_VBR_BUILD = (13, 0, 1, 2067)


def _parse_vbr_build(value: str) -> tuple[int, int, int, int]:
    normalized = value.strip()
    parts = normalized.split(".")
    if len(parts) != 4 or any(not part.isdecimal() for part in parts):
        raise ValueError("VEEAM_BACKEND_BUILD must be a four-part numeric VBR build such as 13.1.1.18")
    build = tuple(int(part) for part in parts)
    if build[0] != 13:
        raise ValueError("Observe v1 supports Veeam Backup & Replication 13 only")
    return build  # type: ignore[return-value]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8098, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    veeam_api_base_url: str = ""
    veeam_username: str = ""
    veeam_password: SecretStr = SecretStr("")
    veeam_backend_read_only: bool = False
    veeam_backend_role: str = ""
    veeam_backend_build: str = ""
    veeam_api_version: str = "1.3-rev2"
    veeam_allow_insecure_http: bool = False
    veeam_tls_verify: bool = True

    veeam_max_page_size: int = Field(default=100, ge=1, le=200)
    veeam_max_sample_size: int = Field(default=50, ge=1, le=200)
    veeam_max_offset: int = Field(default=5_000, ge=0, le=100_000)
    veeam_max_history_hours: int = Field(default=720, ge=1, le=2_160)
    veeam_request_timeout_seconds: float = Field(default=10.0, ge=0.5, le=30.0)
    veeam_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=10_485_760)
    veeam_max_concurrency: int = Field(default=2, ge=1, le=8)
    veeam_rate_limit_per_second: float = Field(default=1.0, ge=0.05, le=20.0)
    veeam_cache_max_age_seconds: int = Field(default=20, ge=0, le=300)

    veeam_budget_max_requests: int = Field(default=6, ge=1, le=30)
    veeam_budget_max_items: int = Field(default=400, ge=1, le=5_000)
    veeam_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    veeam_budget_max_fan_out: int = Field(default=4, ge=1, le=30)
    veeam_budget_timeout_seconds: float = Field(default=35.0, ge=1.0, le=120.0)

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.veeam_api_base_url.strip()
        if value:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("VEEAM_API_BASE_URL must be an absolute HTTP(S) URL")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("VEEAM_API_BASE_URL must not contain credentials, query, or fragment")
            path = parsed.path.rstrip("/")
            if path.endswith("/api") or path.endswith("/api/v1"):
                raise ValueError("VEEAM_API_BASE_URL must be the backup-server origin, not an API path")
            if parsed.scheme == "http" and not self.veeam_allow_insecure_http:
                raise ValueError("plain HTTP requires VEEAM_ALLOW_INSECURE_HTTP=true")
            self.veeam_api_base_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        if self.veeam_api_version != "1.3-rev2":
            raise ValueError("Observe v1 is pinned to the documented VBR 13 REST API 1.3-rev2 contract")

        backend_build = self.veeam_backend_build.strip()
        if backend_build:
            parsed_build = _parse_vbr_build(backend_build)
            if parsed_build < MINIMUM_SECURE_VBR_BUILD:
                raise ValueError(
                    "VEEAM_BACKEND_BUILD is below the minimum secure VBR 13 build 13.0.1.2067"
                )
            self.veeam_backend_build = ".".join(str(part) for part in parsed_build)
        elif self.configured:
            raise ValueError(
                "VEEAM_BACKEND_BUILD is required when the Veeam backend is configured; "
                "attest a patched VBR 13 build >= 13.0.1.2067"
            )
        return self

    @property
    def configured(self) -> bool:
        return bool(
            self.veeam_api_base_url
            and self.veeam_username.strip()
            and self.veeam_password.get_secret_value().strip()
        )

    @property
    def read_only_attested(self) -> bool:
        return self.veeam_backend_read_only and self.veeam_backend_role.strip().casefold() == "backup viewer"

    @property
    def backend_build_attested(self) -> bool:
        return bool(self.veeam_backend_build.strip())
