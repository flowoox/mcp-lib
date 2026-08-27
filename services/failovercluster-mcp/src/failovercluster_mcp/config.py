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


class FailoverClusterTarget(StrictModel):
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
    def validate_transport(self) -> FailoverClusterTarget:
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
    mcp_port: int = Field(default=8093, ge=1, le=65535)
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    failovercluster_backend_read_only: bool = False
    failovercluster_require_jea: bool = True
    failovercluster_powershell_executable: str = "powershell.exe"
    failovercluster_targets_json: str = "{}"

    failovercluster_max_page_size: int = Field(default=100, ge=1, le=500)
    failovercluster_max_sample_size: int = Field(default=50, ge=1, le=500)
    failovercluster_request_timeout_seconds: float = Field(default=20.0, ge=0.5, le=120.0)
    failovercluster_max_response_bytes: int = Field(default=2_097_152, ge=16_384, le=16_777_216)
    failovercluster_max_concurrency: int = Field(default=2, ge=1, le=8)
    failovercluster_rate_limit_per_second: float = Field(default=2.0, ge=0.1, le=20.0)
    failovercluster_cache_max_age_seconds: int = Field(default=5, ge=0, le=300)
    failovercluster_max_event_lookback_minutes: int = Field(default=1_440, ge=1, le=10_080)
    failovercluster_max_group_resources: int = Field(default=64, ge=1, le=256)

    failovercluster_budget_max_requests: int = Field(default=8, ge=1, le=30)
    failovercluster_budget_max_items: int = Field(default=500, ge=1, le=5_000)
    failovercluster_budget_max_response_bytes: int = Field(default=8_388_608, ge=16_384, le=33_554_432)
    failovercluster_budget_max_fan_out: int = Field(default=8, ge=1, le=30)
    failovercluster_budget_timeout_seconds: float = Field(default=45.0, ge=1.0, le=180.0)

    @property
    def targets(self) -> dict[str, FailoverClusterTarget]:
        try:
            raw = json.loads(self.failovercluster_targets_json)
        except json.JSONDecodeError as exc:
            raise ValueError("FAILOVERCLUSTER_TARGETS_JSON must be valid JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise ValueError("FAILOVERCLUSTER_TARGETS_JSON must be a non-empty object")
        if len(raw) > 128:
            raise ValueError("FAILOVERCLUSTER_TARGETS_JSON may contain at most 128 targets")

        targets: dict[str, FailoverClusterTarget] = {}
        for target_id, value in raw.items():
            if not isinstance(target_id, str) or not _TARGET_ID_RE.fullmatch(target_id):
                raise ValueError("Failover Cluster target IDs must match ^[a-z][a-z0-9_.-]{1,63}$")
            target = FailoverClusterTarget.model_validate(value)
            if self.failovercluster_require_jea:
                if target.transport != "winrm":
                    raise ValueError(
                        "FAILOVERCLUSTER_REQUIRE_JEA=true requires every target to use a constrained WinRM/JEA endpoint"
                    )
                assert target.configuration_name is not None
                if target.configuration_name.casefold() in _UNRESTRICTED_ENDPOINTS:
                    raise ValueError("Failover Cluster targets require a dedicated constrained JEA configuration")
            targets[target_id] = target
        return targets
