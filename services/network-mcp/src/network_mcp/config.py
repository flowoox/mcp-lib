from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8085
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    network_allowed_cidrs: str = "127.0.0.0/8,::1/128"
    network_operation_timeout_seconds: float = Field(default=5.0, ge=0.25, le=30.0)
    network_max_resolved_addresses: int = Field(default=16, ge=1, le=64)
    network_max_ports_per_bundle: int = Field(default=8, ge=1, le=32)

    network_path_trace_enabled: bool = False
    network_path_trace_max_hops: int = Field(default=20, ge=1, le=30)
    network_path_trace_process_timeout_seconds: float = Field(default=30.0, ge=1.0, le=60.0)
