from __future__ import annotations

import json
import re
from typing import Literal

from mcp_common.operations import StrictModel
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_TARGET_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_COMPUTER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CONFIGURATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_UNRESTRICTED_ENDPOINTS = {
    "microsoft.powershell",
    "microsoft.powershell32",
    "powershell.7",
}


class WindowsTarget(StrictModel):
    computer_name: str = Field(min_length=1, max_length=253)
    transport: Literal["local", "winrm"] = "winrm"
    configuration_name: str | None = Field(default=None, min_length=1, max_length=64)

    @field_validator("computer_name")
    @classmethod
    def validate_computer_name(cls, value: str) -> str:
        value = value.strip()
        if value == ".":
            return value
        if not _COMPUTER_RE.fullmatch(value):
            raise ValueError("computer_name must be a DNS/NetBIOS hostname or '.'")
        return value

    @field_validator("configuration_name")
    @classmethod
    def validate_configuration_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _CONFIGURATION_RE.fullmatch(value):
            raise ValueError("configuration_name contains unsupported characters")
        return value

    @model_validator(mode="after")
    def validate_transport(self) -> WindowsTarget:
        if self.transport == "local":
            if self.computer_name != ".":
                raise ValueError("local targets must use computer_name='.'")
            if self.configuration_name is not None:
                raise ValueError("local targets must not set configuration_name")
        elif self.configuration_name is None:
            raise ValueError("winrm targets require configuration_name")
        return self


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8089
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    windows_backend_read_only: bool = False
    windows_require_jea: bool = True
    windows_powershell_executable: str = "powershell.exe"
    windows_targets_json: str = '{"local":{"computer_name":".","transport":"local"}}'
    windows_allowed_event_logs: str = "System,Application"

    windows_max_page_size: int = Field(default=100, ge=1, le=500)
    windows_max_sample_size: int = Field(default=50, ge=1, le=500)
    windows_request_timeout_seconds: float = Field(default=12.0, ge=0.5, le=120.0)
    windows_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    windows_max_concurrency: int = Field(default=2, ge=1, le=8)
    windows_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    windows_cache_max_age_seconds: int = Field(default=10, ge=0, le=300)

    windows_budget_max_requests: int = Field(default=8, ge=1, le=30)
    windows_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    windows_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    windows_budget_max_fan_out: int = Field(default=8, ge=1, le=30)
    windows_budget_timeout_seconds: float = Field(default=45.0, ge=1.0, le=180.0)

    @property
    def targets(self) -> dict[str, WindowsTarget]:
        try:
            raw = json.loads(self.windows_targets_json)
        except json.JSONDecodeError as exc:
            raise ValueError("WINDOWS_TARGETS_JSON must be valid JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise ValueError("WINDOWS_TARGETS_JSON must be a non-empty object")
        if len(raw) > 128:
            raise ValueError("WINDOWS_TARGETS_JSON may contain at most 128 targets")
        targets: dict[str, WindowsTarget] = {}
        for target_id, value in raw.items():
            if not isinstance(target_id, str) or not _TARGET_ID_RE.fullmatch(target_id):
                raise ValueError("Windows target IDs must match ^[a-z][a-z0-9_.-]{1,63}$")
            target = WindowsTarget.model_validate(value)
            if self.windows_require_jea and target.transport == "winrm":
                assert target.configuration_name is not None
                if target.configuration_name.casefold() in _UNRESTRICTED_ENDPOINTS:
                    raise ValueError(
                        "remote Windows targets require a dedicated constrained JEA configuration"
                    )
            targets[target_id] = target
        return targets

    @property
    def allowed_event_logs(self) -> frozenset[str]:
        values = [value.strip() for value in self.windows_allowed_event_logs.split(",") if value.strip()]
        if not values:
            raise ValueError("WINDOWS_ALLOWED_EVENT_LOGS must contain at least one log")
        if len(values) > 32:
            raise ValueError("WINDOWS_ALLOWED_EVENT_LOGS may contain at most 32 logs")
        result: set[str] = set()
        for value in values:
            if len(value) > 128 or any(character in value for character in "*?[]{};$`\r\n"):
                raise ValueError("WINDOWS_ALLOWED_EVENT_LOGS contains an unsafe log name")
            result.add(value)
        return frozenset(result)
