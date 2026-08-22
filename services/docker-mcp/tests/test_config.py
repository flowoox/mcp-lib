import pytest
from pydantic import ValidationError

from docker_mcp.client import DockerApiTransport
from docker_mcp.config import Settings, normalize_docker_host


def test_https_and_unix_hosts_are_normalized_without_accepting_unsafe_urls() -> None:
    https = normalize_docker_host("https://docker.example.invalid:2376/")
    assert https.kind == "https"
    assert https.base_url == "https://docker.example.invalid:2376"

    unix = normalize_docker_host("unix:///var/run/docker.sock")
    assert unix.kind == "unix"
    assert unix.socket_path == "/var/run/docker.sock"

    for value in (
        "http://docker.example.invalid",
        "tcp://docker.example.invalid:2375",
        "https://user:pass@docker.example.invalid",
        "https://docker.example.invalid/api",
        "unix://relative/socket",
    ):
        with pytest.raises(ValueError):
            normalize_docker_host(value)


def test_api_version_is_bounded() -> None:
    assert Settings(docker_api_version="v1.47").docker_api_version == "v1.47"
    with pytest.raises(ValidationError):
        Settings(docker_api_version="latest")
    with pytest.raises(ValidationError):
        Settings(docker_api_version="v1.23")


def test_transport_fails_closed_without_read_only_attestation() -> None:
    with pytest.raises(ValueError, match="BACKEND_READ_ONLY"):
        DockerApiTransport(Settings(docker_host="https://docker.example.invalid"))


def test_direct_socket_requires_separate_privileged_override() -> None:
    settings = Settings(
        docker_host="unix:///var/run/docker.sock",
        docker_backend_read_only=True,
    )
    with pytest.raises(ValueError, match="direct Docker sockets are disabled"):
        DockerApiTransport(settings)
