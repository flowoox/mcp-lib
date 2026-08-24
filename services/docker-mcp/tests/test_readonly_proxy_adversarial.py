from __future__ import annotations

import json
from urllib.parse import urlencode

from docker_mcp.readonly_proxy import DockerReadOnlyPolicy


def _policy() -> DockerReadOnlyPolicy:
    return DockerReadOnlyPolicy(
        api_version="v1.47",
        max_page_size=100,
        max_log_window_seconds=3_600,
        max_event_window_seconds=300,
    )


def test_event_filter_with_non_string_values_fails_closed() -> None:
    target = "/v1.47/events?" + urlencode(
        {
            "since": "1000",
            "until": "1100",
            "filters": json.dumps({"type": [{"unexpected": "object"}]}),
        }
    )
    decision = _policy().authorize("GET", target)
    assert decision.allowed is False
    assert decision.reason == "query_not_allowed"


def test_api_version_constructor_is_fail_closed() -> None:
    for version in ("v1.00", "v1.23", "v1.100", "latest", "v2.00"):
        try:
            DockerReadOnlyPolicy(
                api_version=version,
                max_page_size=100,
                max_log_window_seconds=3_600,
                max_event_window_seconds=300,
            )
        except ValueError:
            continue
        raise AssertionError(f"unexpectedly accepted API version {version}")
