from __future__ import annotations

import re
import ssl
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_VDOM_RE = re.compile(r"^[A-Za-z0-9_. -]{1,79}$")


def normalize_base_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("FORTIGATE_BASE_URL must be configured")
    if any(ord(character) < 32 for character in raw):
        raise ValueError("FORTIGATE_BASE_URL must not contain control characters")
    parsed = urlsplit(raw)
    if parsed.scheme != "https":
        raise ValueError("FORTIGATE_BASE_URL must use https://")
    if parsed.username or parsed.password:
        raise ValueError("FORTIGATE_BASE_URL must not contain URL userinfo")
    if not parsed.hostname or parsed.path not in {"", "/"}:
        raise ValueError("FORTIGATE_BASE_URL must be a bare HTTPS origin")
    if parsed.query or parsed.fragment:
        raise ValueError("FORTIGATE_BASE_URL must not contain a query or fragment")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("FORTIGATE_BASE_URL contains an invalid port") from exc
    return raw.rstrip("/")


def parse_allowed_vdoms(value: str) -> frozenset[str]:
    entries = [item.strip() for item in value.split(";") if item.strip()]
    if not entries:
        raise ValueError("FORTIGATE_ALLOWED_VDOMS must contain at least one VDOM")
    for entry in entries:
        if _VDOM_RE.fullmatch(entry) is None:
            raise ValueError("FORTIGATE_ALLOWED_VDOMS contains an invalid VDOM name")
    return frozenset(entries)


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

    fortigate_base_url: str = ""
    fortigate_api_token: SecretStr = SecretStr("")
    fortigate_backend_read_only: bool = False
    fortigate_default_vdom: str = "root"
    fortigate_allowed_vdoms: str = "root"
    fortigate_tls_verify: bool = True
    fortigate_allow_insecure_tls: bool = False
    fortigate_ca_bundle: str = ""

    fortigate_max_page_size: int = Field(default=100, ge=1, le=500)
    fortigate_max_sample_size: int = Field(default=50, ge=1, le=500)
    fortigate_request_timeout_seconds: float = Field(default=8.0, ge=0.5, le=60.0)
    fortigate_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    fortigate_max_concurrency: int = Field(default=2, ge=1, le=8)
    fortigate_rate_limit_per_second: float = Field(default=3.0, ge=0.1, le=50.0)
    fortigate_cache_max_age_seconds: int = Field(default=5, ge=0, le=300)

    fortigate_budget_max_requests: int = Field(default=8, ge=1, le=20)
    fortigate_budget_max_items: int = Field(default=400, ge=1, le=2_000)
    fortigate_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    fortigate_budget_max_fan_out: int = Field(default=8, ge=1, le=20)
    fortigate_budget_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    @field_validator("fortigate_default_vdom")
    @classmethod
    def validate_default_vdom(cls, value: str) -> str:
        normalized = value.strip()
        if _VDOM_RE.fullmatch(normalized) is None:
            raise ValueError("FORTIGATE_DEFAULT_VDOM contains an invalid VDOM name")
        return normalized

    def allowed_vdoms(self) -> frozenset[str]:
        return parse_allowed_vdoms(self.fortigate_allowed_vdoms)

    def resolve_vdom(self, value: str | None) -> str:
        selected = (value or self.fortigate_default_vdom).strip()
        if selected not in self.allowed_vdoms():
            raise PermissionError("requested VDOM is outside FORTIGATE_ALLOWED_VDOMS")
        return selected

    def tls_verify_value(self) -> ssl.SSLContext | bool:
        if self.fortigate_ca_bundle:
            bundle = Path(self.fortigate_ca_bundle)
            if not bundle.is_file():
                raise ValueError("FORTIGATE_CA_BUNDLE must reference an existing file")
            return ssl.create_default_context(cafile=str(bundle))
        if self.fortigate_tls_verify:
            return True
        if not self.fortigate_allow_insecure_tls:
            raise ValueError(
                "FORTIGATE_TLS_VERIFY=false requires FORTIGATE_ALLOW_INSECURE_TLS=true"
            )
        return False
