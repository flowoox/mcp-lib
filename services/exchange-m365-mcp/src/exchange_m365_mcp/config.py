from __future__ import annotations

import re
from typing import Literal
from uuid import UUID

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.onmicrosoft\.com$")
_THUMBPRINT_RE = re.compile(r"^[A-Fa-f0-9]{40,128}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8103, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    exchange_backend_read_only: bool = False
    exchange_view_only_rbac_attested: bool = False
    exchange_powershell_executable: str = "pwsh"
    exchange_organization: str = ""
    exchange_app_id: str = ""
    exchange_certificate_thumbprint: str = ""
    exchange_return_domain_names: bool = False

    m365_graph_backend_read_only: bool = False
    m365_graph_service_health_permission_attested: bool = False
    m365_graph_tenant_id: str = ""
    m365_graph_client_id: str = ""
    m365_graph_client_secret: SecretStr = SecretStr("")

    exchange_max_page_size: int = Field(default=100, ge=1, le=500)
    exchange_max_sample_size: int = Field(default=50, ge=1, le=100)
    exchange_request_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    exchange_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    exchange_max_concurrency: int = Field(default=1, ge=1, le=4)
    exchange_rate_limit_per_second: float = Field(default=0.5, ge=0.05, le=5.0)
    exchange_cache_max_age_seconds: int = Field(default=30, ge=0, le=300)

    graph_max_page_size: int = Field(default=100, ge=1, le=500)
    graph_max_sample_size: int = Field(default=50, ge=1, le=100)
    graph_request_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    graph_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    graph_max_concurrency: int = Field(default=1, ge=1, le=4)
    graph_rate_limit_per_second: float = Field(default=1.0, ge=0.05, le=10.0)
    graph_cache_max_age_seconds: int = Field(default=60, ge=0, le=600)

    m365_budget_max_requests: int = Field(default=10, ge=1, le=30)
    m365_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    m365_budget_max_response_bytes: int = Field(default=12_582_912, ge=16_384, le=67_108_864)
    m365_budget_max_fan_out: int = Field(default=6, ge=1, le=16)
    m365_budget_timeout_seconds: float = Field(default=90.0, ge=1.0, le=240.0)

    @field_validator("exchange_organization")
    @classmethod
    def validate_exchange_organization(cls, value: str) -> str:
        value = value.strip()
        if value and not _ORG_RE.fullmatch(value):
            raise ValueError("EXCHANGE_ORGANIZATION must be the tenant .onmicrosoft.com domain")
        return value.lower()

    @field_validator("exchange_app_id", "m365_graph_tenant_id", "m365_graph_client_id")
    @classmethod
    def validate_uuid_if_present(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return value
        try:
            return str(UUID(value))
        except ValueError as exc:
            raise ValueError("configured application and tenant identifiers must be UUIDs") from exc

    @field_validator("exchange_certificate_thumbprint")
    @classmethod
    def validate_thumbprint(cls, value: str) -> str:
        normalized = value.replace(" ", "").strip()
        if normalized and not _THUMBPRINT_RE.fullmatch(normalized):
            raise ValueError("EXCHANGE_CERTIFICATE_THUMBPRINT must be a hexadecimal thumbprint")
        return normalized.upper()

    @property
    def exchange_configured(self) -> bool:
        return bool(
            self.exchange_organization
            and self.exchange_app_id
            and self.exchange_certificate_thumbprint
        )

    @property
    def graph_configured(self) -> bool:
        return bool(
            self.m365_graph_tenant_id
            and self.m365_graph_client_id
            and self.m365_graph_client_secret.get_secret_value()
        )
