from __future__ import annotations

import json
import re
from typing import Literal

from mcp_common.operations import StrictModel
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_TARGET_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_COMPUTER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CONFIGURATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_CA_CONFIG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\[^\\\x00-\x1f]{1,128}$")
_UNRESTRICTED_ENDPOINTS = {
    "microsoft.powershell",
    "microsoft.powershell32",
    "powershell.7",
}


class PKITarget(StrictModel):
    computer_name: str = Field(min_length=1, max_length=253)
    configuration_name: str = Field(min_length=1, max_length=64)
    ca_config: str = Field(min_length=3, max_length=382)

    @field_validator("computer_name")
    @classmethod
    def validate_computer_name(cls, value: str) -> str:
        value = value.strip()
        if not _COMPUTER_RE.fullmatch(value):
            raise ValueError("computer_name must be a DNS/NetBIOS hostname")
        return value

    @field_validator("configuration_name")
    @classmethod
    def validate_configuration_name(cls, value: str) -> str:
        value = value.strip()
        if not _CONFIGURATION_RE.fullmatch(value):
            raise ValueError("configuration_name contains unsupported characters")
        if value.casefold() in _UNRESTRICTED_ENDPOINTS:
            raise ValueError("PKI targets require a dedicated constrained JEA configuration")
        return value

    @field_validator("ca_config")
    @classmethod
    def validate_ca_config(cls, value: str) -> str:
        value = value.strip()
        if not _CA_CONFIG_RE.fullmatch(value):
            raise ValueError("ca_config must use the exact ServerName\\CAName form")
        return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8102, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    pki_backend_read_only: bool = False
    pki_backend_view_ca_database_attested: bool = False
    pki_powershell_executable: str = "powershell.exe"
    pki_targets_json: str = "{}"

    pki_max_page_size: int = Field(default=100, ge=1, le=250)
    pki_max_sample_size: int = Field(default=50, ge=1, le=100)
    pki_request_timeout_seconds: float = Field(default=20.0, ge=0.5, le=120.0)
    pki_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    pki_max_concurrency: int = Field(default=1, ge=1, le=4)
    pki_rate_limit_per_second: float = Field(default=0.5, ge=0.05, le=5.0)
    pki_cache_max_age_seconds: int = Field(default=15, ge=0, le=300)
    pki_max_expiry_days: int = Field(default=180, ge=1, le=730)
    pki_max_event_lookback_minutes: int = Field(default=1_440, ge=1, le=10_080)

    pki_budget_max_requests: int = Field(default=6, ge=1, le=20)
    pki_budget_max_items: int = Field(default=300, ge=1, le=2_000)
    pki_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    pki_budget_max_fan_out: int = Field(default=4, ge=1, le=12)
    pki_budget_timeout_seconds: float = Field(default=45.0, ge=1.0, le=180.0)

    @property
    def targets(self) -> dict[str, PKITarget]:
        try:
            raw = json.loads(self.pki_targets_json)
        except json.JSONDecodeError as exc:
            raise ValueError("PKI_TARGETS_JSON must be valid JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise ValueError("PKI_TARGETS_JSON must be a non-empty object")
        if len(raw) > 64:
            raise ValueError("PKI_TARGETS_JSON may contain at most 64 targets")
        targets: dict[str, PKITarget] = {}
        for target_id, value in raw.items():
            if not isinstance(target_id, str) or not _TARGET_ID_RE.fullmatch(target_id):
                raise ValueError("PKI target IDs must match ^[a-z][a-z0-9_.-]{1,63}$")
            targets[target_id] = PKITarget.model_validate(value)
        return targets
