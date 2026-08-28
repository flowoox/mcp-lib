from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8094, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    n8n_api_base_url: str = ""
    n8n_api_key: SecretStr = SecretStr("")
    n8n_backend_read_only: bool = False
    n8n_allow_insecure_http: bool = False
    n8n_tls_verify: bool = True
    n8n_allowed_workflow_ids: str = ""

    n8n_max_page_size: int = Field(default=100, ge=1, le=250)
    n8n_max_sample_size: int = Field(default=50, ge=1, le=250)
    n8n_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    n8n_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    n8n_max_concurrency: int = Field(default=2, ge=1, le=8)
    n8n_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    n8n_cache_max_age_seconds: int = Field(default=10, ge=0, le=300)

    n8n_budget_max_requests: int = Field(default=6, ge=1, le=30)
    n8n_budget_max_items: int = Field(default=300, ge=1, le=5_000)
    n8n_budget_max_response_bytes: int = Field(default=6_291_456, ge=16_384, le=33_554_432)
    n8n_budget_max_fan_out: int = Field(default=6, ge=1, le=30)
    n8n_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @field_validator("n8n_allowed_workflow_ids")
    @classmethod
    def validate_allowed_workflow_ids(cls, value: str) -> str:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) > 500:
            raise ValueError("N8N_ALLOWED_WORKFLOW_IDS cannot contain more than 500 IDs")
        for part in parts:
            if len(part) > 128 or any(character.isspace() for character in part):
                raise ValueError("workflow IDs must be non-empty, whitespace-free, and <=128 characters")
        return ",".join(dict.fromkeys(parts))

    @model_validator(mode="after")
    def validate_endpoint(self) -> Self:
        value = self.n8n_api_base_url.strip()
        if not value:
            return self
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("N8N_API_BASE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("N8N_API_BASE_URL must not contain credentials, query, or fragment")
        normalized_path = parsed.path.rstrip("/")
        if not normalized_path.endswith("/api/v1"):
            raise ValueError("N8N_API_BASE_URL must end with /api/v1")
        if "/../" in f"{normalized_path}/" or "/./" in f"{normalized_path}/":
            raise ValueError("N8N_API_BASE_URL path cannot contain dot segments")
        if parsed.scheme == "http" and not self.n8n_allow_insecure_http:
            raise ValueError("plain HTTP requires N8N_ALLOW_INSECURE_HTTP=true")
        self.n8n_api_base_url = urlunsplit(
            (parsed.scheme, parsed.netloc, normalized_path, "", "")
        )
        return self

    @property
    def configured(self) -> bool:
        return bool(self.n8n_api_base_url and self.n8n_api_key.get_secret_value().strip())

    @property
    def allowed_workflow_ids(self) -> frozenset[str]:
        return frozenset(part for part in self.n8n_allowed_workflow_ids.split(",") if part)
