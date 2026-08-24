from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

import pytest

from docker_mcp.readonly_proxy import (
    DockerReadOnlyPolicy,
    ProxyConfig,
    _load_bearer_token,
)


def policy() -> DockerReadOnlyPolicy:
    return DockerReadOnlyPolicy(
        api_version="v1.47",
        max_page_size=100,
        max_log_window_seconds=3_600,
        max_event_window_seconds=300,
    )


def allowed(target: str) -> bool:
    return policy().authorize("GET", target).allowed


def test_policy_allows_only_the_fixed_mcp_get_surface() -> None:
    event_filters = json.dumps({"type": ["container"]}, separators=(",", ":"))
    assert allowed("/_ping")
    assert allowed("/v1.47/info")
    assert allowed("/v1.47/containers/json?all=false&limit=50")
    assert allowed(
        "/v1.47/containers/web-01/logs?"
        + urlencode(
            {
                "stdout": "true",
                "stderr": "true",
                "timestamps": "true",
                "tail": "50",
                "since": "1000",
                "until": "1300",
            }
        )
    )
    assert allowed("/v1.47/containers/web-01/stats?stream=false&one-shot=true")
    assert allowed("/v1.47/images/json?all=false")
    assert allowed("/v1.47/volumes")
    assert allowed("/v1.47/networks")
    assert allowed(
        "/v1.47/events?"
        + urlencode({"since": "1000", "until": "1100", "filters": event_filters})
    )


def test_policy_rejects_methods_versions_paths_and_arbitrary_query_keys() -> None:
    value = policy()
    assert not value.authorize("POST", "/v1.47/info").allowed
    assert not value.authorize("DELETE", "/v1.47/containers/web-01").allowed
    assert not value.authorize("GET", "/v1.46/info").allowed
    assert not value.authorize("GET", "/v1.47/version").allowed
    assert not value.authorize("GET", "/v1.47/containers/web-01/json").allowed
    assert not value.authorize("GET", "https://docker.invalid/v1.47/info").allowed
    assert not value.authorize("GET", "/v1.47/info#fragment").allowed
    assert not value.authorize("GET", "/v1.47/containers/json?all=false&limit=5&filters=x").allowed
    assert not value.authorize("GET", "/v1.47/containers/json?all=false&limit=5&limit=6").allowed


def test_policy_enforces_page_log_stats_and_container_target_bounds() -> None:
    assert not allowed("/v1.47/containers/json?all=false&limit=101")
    assert not allowed("/v1.47/containers/json?all=1&limit=5")
    assert not allowed("/v1.47/containers/web%2F..%2Fsecret/stats?stream=false&one-shot=true")
    assert not allowed("/v1.47/containers/web-01/stats?stream=true&one-shot=true")
    assert not allowed(
        "/v1.47/containers/web-01/logs?"
        + urlencode(
            {
                "stdout": "true",
                "stderr": "true",
                "timestamps": "true",
                "tail": "101",
                "since": "1000",
                "until": "1100",
            }
        )
    )
    assert not allowed(
        "/v1.47/containers/web-01/logs?"
        + urlencode(
            {
                "stdout": "true",
                "stderr": "true",
                "timestamps": "true",
                "tail": "50",
                "since": "1000",
                "until": "5000",
            }
        )
    )
    assert not allowed(
        "/v1.47/containers/web-01/logs?"
        + urlencode(
            {
                "stdout": "true",
                "stderr": "true",
                "timestamps": "true",
                "tail": "50",
                "since": "1000",
                "until": "1100",
                "follow": "true",
            }
        )
    )


def test_policy_enforces_image_and_event_filters() -> None:
    assert not allowed("/v1.47/images/json?all=true")
    assert not allowed("/v1.47/volumes?filters=%7B%7D")
    assert not allowed(
        "/v1.47/events?"
        + urlencode(
            {
                "since": "1000",
                "until": "1400",
                "filters": json.dumps({"type": ["container"]}),
            }
        )
    )
    assert not allowed(
        "/v1.47/events?"
        + urlencode(
            {
                "since": "1000",
                "until": "1100",
                "filters": json.dumps({"type": ["plugin"]}),
            }
        )
    )
    assert not allowed(
        "/v1.47/events?"
        + urlencode(
            {
                "since": "1000",
                "until": "1100",
                "filters": json.dumps({"type": ["container"], "event": ["die"]}),
            }
        )
    )


def test_proxy_config_is_product_neutral_bounded_and_fail_closed() -> None:
    env = {
        "DOCKER_READONLY_PROXY_DOCKER_SOCKET": "/run/docker.sock",
        "DOCKER_READONLY_PROXY_TLS_CERT_FILE": "/run/secrets/proxy.crt",
        "DOCKER_READONLY_PROXY_TLS_KEY_FILE": "/run/secrets/proxy.key",
        "DOCKER_READONLY_PROXY_BEARER_TOKEN_FILE": "/run/secrets/proxy.token",
    }
    config = ProxyConfig.from_env(env)
    assert config.bind_host == "127.0.0.1"
    assert config.bind_port == 23760
    assert config.api_version == "v1.47"
    assert config.max_page_size == 100
    assert config.max_concurrency == 4

    with pytest.raises(ValueError, match="TLS_CERT_FILE"):
        ProxyConfig.from_env(
            {
                "DOCKER_READONLY_PROXY_DOCKER_SOCKET": "/run/docker.sock",
                "DOCKER_READONLY_PROXY_TLS_KEY_FILE": "/run/secrets/proxy.key",
                "DOCKER_READONLY_PROXY_BEARER_TOKEN_FILE": "/run/secrets/proxy.token",
            }
        )
    with pytest.raises(ValueError, match="MAX_PAGE_SIZE"):
        ProxyConfig.from_env({**env, "DOCKER_READONLY_PROXY_MAX_PAGE_SIZE": "501"})
    with pytest.raises(ValueError, match="absolute literal POSIX path"):
        ProxyConfig.from_env({**env, "DOCKER_READONLY_PROXY_DOCKER_SOCKET": "../docker.sock"})


def test_proxy_bearer_token_is_loaded_from_file_and_rejects_weak_values(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("a" * 48 + "\n", encoding="utf-8")
    assert _load_bearer_token(str(token_file)) == "a" * 48

    token_file.write_text("too-short", encoding="utf-8")
    with pytest.raises(ValueError, match="32-4096"):
        _load_bearer_token(str(token_file))

    token_file.write_text("a" * 32 + " internal-space", encoding="utf-8")
    with pytest.raises(ValueError, match="without whitespace"):
        _load_bearer_token(str(token_file))
