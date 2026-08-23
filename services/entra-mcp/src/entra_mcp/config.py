from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Cloud = Literal["global", "usgov", "dod", "china"]

_CLOUD_ENDPOINTS: dict[str, tuple[str, str]] = {
    "global": ("https://login.microsoftonline.com", "https://graph.microsoft.com"),
    "usgov": ("https://login.microsoftonline.us", "https://graph.microsoft.us"),
    "dod": ("https://login.microsoftonline.us", "https://dod-graph.microsoft.us"),
    "china": ("https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"),
}


def _guid(value: str, field_name: str) -> str:
    normalized = value.strip()
    try:
        parsed = UUID(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a GUID") from exc
    return str(parsed)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8088
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    entra_cloud: Cloud = "global"
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: SecretStr = SecretStr("")
    entra_backend_read_only: bool = False

    entra_max_page_size: int = Field(default=100, ge=1, le=500)
    entra_max_sample_size: int = Field(default=50, ge=1, le=500)
    entra_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    entra_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    entra_max_concurrency: int = Field(default=2, ge=1, le=8)
    entra_rate_limit_per_second: float = Field(default=4.0, ge=0.1, le=50.0)
    entra_cache_max_age_seconds: int = Field(default=10, ge=0, le=300)

    entra_budget_max_requests: int = Field(default=10, ge=1, le=30)
    entra_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    entra_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    entra_budget_max_fan_out: int = Field(default=10, ge=1, le=30)
    entra_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @field_validator("entra_tenant_id")
    @classmethod
    def validate_tenant_id(cls, value: str) -> str:
        if not value.strip():
            return ""
        return _guid(value, "ENTRA_TENANT_ID")

    @field_validator("entra_client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        if not value.strip():
            return ""
        return _guid(value, "ENTRA_CLIENT_ID")

    @property
    def authority_origin(self) -> str:
        return _CLOUD_ENDPOINTS[self.entra_cloud][0]

    @property
    def graph_origin(self) -> str:
        return _CLOUD_ENDPOINTS[self.entra_cloud][1]

    @property
    def token_url(self) -> str:
        if not self.entra_tenant_id:
            raise ValueError("ENTRA_TENANT_ID must be configured")
        return f"{self.authority_origin}/{self.entra_tenant_id}/oauth2/v2.0/token"

    @property
    def configured(self) -> bool:
        return bool(
            self.entra_tenant_id
            and self.entra_client_id
            and self.entra_client_secret.get_secret_value().strip()
        )
