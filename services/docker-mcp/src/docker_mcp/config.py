from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_API_VERSION_RE = re.compile(r"^v1\.(\d{2})$")


@dataclass(frozen=True)
class DockerEndpoint:
    kind: Literal["https", "unix"]
    base_url: str
    socket_path: str | None = None


def normalize_docker_host(value: str) -> DockerEndpoint:
    raw = value.strip()
    if not raw:
        raise ValueError("DOCKER_HOST must be configured")
    if any(ord(character) < 32 for character in raw):
        raise ValueError("DOCKER_HOST must not contain control characters")
    parsed = urlsplit(raw)
    if parsed.username or parsed.password:
        raise ValueError("DOCKER_HOST must not contain URL userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("DOCKER_HOST must not contain a query or fragment")

    if parsed.scheme == "unix":
        if parsed.netloc or not parsed.path or not PurePosixPath(parsed.path).is_absolute():
            raise ValueError("unix DOCKER_HOST must contain one absolute socket path")
        if "%" in parsed.path or "\\" in parsed.path:
            raise ValueError("unix DOCKER_HOST socket path must be literal POSIX path text")
        return DockerEndpoint(kind="unix", base_url="http://docker", socket_path=parsed.path)

    if parsed.scheme != "https":
        raise ValueError("DOCKER_HOST must use https:// or an explicitly enabled unix:// socket")
    if not parsed.hostname or parsed.path not in {"", "/"}:
        raise ValueError("https DOCKER_HOST must be a bare origin without an application path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("DOCKER_HOST contains an invalid port") from exc
    return DockerEndpoint(kind="https", base_url=raw.rstrip("/"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")

    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8086
    mcp_trust_boundary: Literal["internal", "external"] = "internal"
    mcp_allowed_hosts: str = ""
    mcp_allowed_origins: str = ""
    mcp_public_url: str = ""
    mcp_issuer_url: str = ""
    mcp_auth_token: str = ""

    docker_host: str = ""
    docker_backend_read_only: bool = False
    docker_allow_direct_socket: bool = False
    docker_auth_token: SecretStr = SecretStr("")
    docker_tls_verify: bool = True
    docker_allow_insecure_tls: bool = False
    docker_api_version: str = "v1.47"

    docker_max_page_size: int = Field(default=100, ge=1, le=500)
    docker_max_sample_size: int = Field(default=50, ge=1, le=500)
    docker_request_timeout_seconds: float = Field(default=5.0, ge=0.25, le=30.0)
    docker_max_response_bytes: int = Field(
        default=1_048_576,
        ge=16_384,
        le=16_777_216,
    )
    docker_max_concurrency: int = Field(default=2, ge=1, le=8)
    docker_rate_limit_per_second: float = Field(default=4.0, ge=0.1, le=100.0)
    docker_cache_max_age_seconds: int = Field(default=5, ge=0, le=300)
    docker_max_log_window_seconds: int = Field(default=3_600, ge=1, le=86_400)
    docker_max_log_line_chars: int = Field(default=2_000, ge=128, le=8_192)
    docker_max_event_window_seconds: int = Field(default=300, ge=1, le=3_600)

    docker_budget_max_requests: int = Field(default=4, ge=1, le=20)
    docker_budget_max_items: int = Field(default=200, ge=1, le=1_000)
    docker_budget_max_response_bytes: int = Field(
        default=2_097_152,
        ge=16_384,
        le=33_554_432,
    )
    docker_budget_max_fan_out: int = Field(default=4, ge=1, le=20)
    docker_budget_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)

    @field_validator("docker_api_version")
    @classmethod
    def validate_api_version(cls, value: str) -> str:
        match = _API_VERSION_RE.fullmatch(value.strip())
        if match is None or not 24 <= int(match.group(1)) <= 99:
            raise ValueError("DOCKER_API_VERSION must be between v1.24 and v1.99")
        return value.strip()
