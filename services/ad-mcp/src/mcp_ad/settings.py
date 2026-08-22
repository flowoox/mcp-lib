from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration.

    The service is read-only, but directory credentials still grant sensitive
    visibility. TLS is therefore mandatory unless an operator explicitly opts
    into insecure transport for an isolated development environment.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    ad_host: str = Field(min_length=1)
    ad_port: int = Field(default=636, ge=1, le=65535)
    ad_use_ssl: bool = True
    ad_start_tls: bool = False
    ad_allow_insecure: bool = False
    ad_validate_certificate: bool = True
    ad_ca_file: Path | None = None
    ad_server_name: str | None = None
    ad_bind_dn: str = Field(min_length=1)
    ad_bind_password: SecretStr
    ad_base_dn: str = Field(min_length=3)
    ad_allowed_base_dns: str = ""
    ad_privileged_group_dns: str = ""
    ad_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    ad_receive_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    ad_max_results: int = Field(default=200, ge=1, le=1000)
    ad_stale_days: int = Field(default=90, ge=30, le=3650)
    ad_min_password_length: int = Field(default=14, ge=8, le=128)

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8091, ge=1, le=65535)
    mcp_transport: str = "streamable-http"
    mcp_trust_boundary: str = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_auth_token: SecretStr | None = None
    mcp_issuer_url: str = ""

    @field_validator(
        "ad_host",
        "ad_bind_dn",
        "ad_base_dn",
        "ad_allowed_base_dns",
        "ad_privileged_group_dns",
        "mcp_host",
        "mcp_transport",
        "mcp_trust_boundary",
        "mcp_allowed_hosts",
        "mcp_allowed_origins",
        "mcp_public_url",
        "mcp_issuer_url",
        mode="before",
    )
    @classmethod
    def strip_strings(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_transport(self) -> Settings:
        if self.ad_use_ssl and self.ad_start_tls:
            raise ValueError("Choose AD_USE_SSL or AD_START_TLS, not both")
        if not self.ad_use_ssl and not self.ad_start_tls and not self.ad_allow_insecure:
            raise ValueError(
                "Plain LDAP is disabled; enable AD_USE_SSL or AD_START_TLS. "
                "AD_ALLOW_INSECURE is only for isolated development."
            )
        if self.ad_validate_certificate and self.ad_ca_file is not None:
            if not self.ad_ca_file.is_file():
                raise ValueError("AD_CA_FILE does not exist or is not a file")
        if self.mcp_transport not in {"stdio", "streamable-http"}:
            raise ValueError("MCP_TRANSPORT must be stdio or streamable-http")
        return self

    @property
    def allowed_base_dns(self) -> tuple[str, ...]:
        configured = [item.strip() for item in self.ad_allowed_base_dns.split(";") if item.strip()]
        return tuple(dict.fromkeys([self.ad_base_dn, *configured]))

    @property
    def privileged_group_dns(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                item.strip() for item in self.ad_privileged_group_dns.split(";") if item.strip()
            )
        )

    @property
    def bind_password(self) -> str:
        return self.ad_bind_password.get_secret_value()

    @property
    def auth_token(self) -> str:
        return self.mcp_auth_token.get_secret_value() if self.mcp_auth_token else ""
