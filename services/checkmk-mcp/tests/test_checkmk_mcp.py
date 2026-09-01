from __future__ import annotations

import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery
from pydantic import ValidationError

from checkmk_mcp.client import CheckmkClientError, CheckmkReadOnlyTransport
from checkmk_mcp.config import Settings
from checkmk_mcp.contract import capabilities
from checkmk_mcp.server import _budget_limits, _connector_policy


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "checkmk_api_base_url": "https://monitor.example/mysite/check_mk/api/1.0",
        "checkmk_username": "svc-mcp-checkmk",
        "checkmk_automation_secret": "secret-token",
        "checkmk_backend_read_only": True,
        "checkmk_backend_role": "mcp_monitoring_observer",
    }
    values.update(overrides)
    return Settings(**values)


def _host_row(name: str, state: int) -> dict[str, object]:
    return {
        "id": name,
        "title": name,
        "extensions": {
            "name": name,
            "state": state,
            "acknowledged": 0,
            "in_downtime": 0,
            "is_flapping": 0,
            "stale": 0,
            "last_check": 1_780_000_000,
            "last_state_change": 1_779_999_000,
            "address": "192.0.2.44",
            "contacts": ["admin"],
            "plugin_output": "must not escape",
        },
    }


def _service_row(host: str, description: str, state: int) -> dict[str, object]:
    return {
        "id": f"{host}:{description}",
        "extensions": {
            "host_name": host,
            "description": description,
            "state": state,
            "acknowledged": 1,
            "in_downtime": 0,
            "is_flapping": 0,
            "stale": 0,
            "last_check": 1_780_000_000,
            "last_state_change": 1_779_999_000,
            "plugin_output": "database password-like content",
            "perf_data": "load=99",
            "comments": ["private note"],
            "contacts": ["operator"],
        },
    }


def test_config_requires_stable_api_root_and_explicit_http_override() -> None:
    with pytest.raises(ValidationError, match="stable /check_mk/api/1.0"):
        _settings(checkmk_api_base_url="https://monitor.example/mysite/check_mk/api/unstable")
    with pytest.raises(ValidationError, match="plain HTTP"):
        _settings(checkmk_api_base_url="http://monitor.example/mysite/check_mk/api/1.0")
    settings = _settings(
        checkmk_api_base_url="http://monitor.example/mysite/check_mk/api/1.0/",
        checkmk_allow_insecure_http=True,
    )
    assert settings.checkmk_api_base_url.endswith("/check_mk/api/1.0")


def test_transport_fails_closed_without_read_only_attestation_or_role() -> None:
    with pytest.raises(ValueError, match="BACKEND_READ_ONLY"):
        CheckmkReadOnlyTransport(_settings(checkmk_backend_read_only=False))
    with pytest.raises(ValueError, match="CHECKMK_BACKEND_ROLE"):
        CheckmkReadOnlyTransport(_settings(checkmk_backend_role=""))


@pytest.mark.asyncio
async def test_problem_host_query_is_fixed_bounded_and_privacy_minimized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path.endswith("/domain-types/host/collections/all")
        assert request.headers["Authorization"] == "Bearer svc-mcp-checkmk secret-token"
        body = json.loads(request.content)
        assert body["query"] == {"op": "!=", "left": "state", "right": "0"}
        assert body["columns"] == [
            "name",
            "state",
            "acknowledged",
            "in_downtime",
            "is_flapping",
            "stale",
            "last_check",
            "last_state_change",
        ]
        return httpx.Response(
            200,
            json={"value": [_host_row("edge-01", 1), _host_row("edge-02", 2)]},
        )

    transport = CheckmkReadOnlyTransport(
        _settings(), transport=httpx.MockTransport(handler)
    )
    page = await transport.query(
        ReadOnlyQuery(
            operation="checkmk.problem_hosts.list",
            page=PageRequest(limit=1),
        ),
        timeout_seconds=2,
        max_response_bytes=65_536,
    )
    assert page.truncated is True
    assert len(page.items) == 1
    item = page.items[0]
    assert item["host_name"] == "edge-01"
    assert item["state_label"] == "DOWN"
    assert "address" not in item
    assert "contacts" not in item
    assert "plugin_output" not in item


@pytest.mark.asyncio
async def test_problem_service_drilldown_uses_fixed_host_path_and_excludes_raw_output() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path.endswith("/objects/host/db-01/collections/services")
        body = json.loads(request.content)
        assert body["query"] == {"op": "!=", "left": "state", "right": "0"}
        assert "plugin_output" not in body["columns"]
        assert "perf_data" not in body["columns"]
        return httpx.Response(200, json={"value": [_service_row("db-01", "PostgreSQL", 2)]})

    transport = CheckmkReadOnlyTransport(
        _settings(), transport=httpx.MockTransport(handler)
    )
    page = await transport.query(
        ReadOnlyQuery(
            operation="checkmk.host.problem_services",
            parameters={"host_name": "db-01"},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=2,
        max_response_bytes=65_536,
    )
    assert page.items[0]["state_label"] == "CRIT"
    assert page.items[0]["acknowledged"] is True
    assert "plugin_output" not in page.items[0]
    assert "perf_data" not in page.items[0]
    assert "comments" not in page.items[0]
    assert "contacts" not in page.items[0]


@pytest.mark.asyncio
async def test_version_observation_and_fixed_operation_allowlist() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path.endswith("/check_mk/api/1.0/version")
        return httpx.Response(
            200,
            json={"versions": {"checkmk": "2.5.0p17", "edition": "community"}},
        )

    transport = CheckmkReadOnlyTransport(
        _settings(), transport=httpx.MockTransport(handler)
    )
    page = await transport.query(
        ReadOnlyQuery(operation="checkmk.version.get", page=PageRequest(limit=1)),
        timeout_seconds=2,
        max_response_bytes=65_536,
    )
    assert page.items == [{"version": "2.5.0p17", "edition": "community"}]
    with pytest.raises(PermissionError, match="fixed read-only"):
        await transport.query(
            ReadOnlyQuery(operation="checkmk.configuration.write"),
            timeout_seconds=2,
            max_response_bytes=65_536,
        )


@pytest.mark.asyncio
async def test_adapter_rejects_caller_query_dsl_redirects_and_cross_host_rows() -> None:
    transport = CheckmkReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "https://evil.example/"})),
    )
    with pytest.raises(ValueError, match="unsupported parameters"):
        await transport.query(
            ReadOnlyQuery(
                operation="checkmk.problem_services.list",
                parameters={"query": {"op": "="}},
            ),
            timeout_seconds=2,
            max_response_bytes=65_536,
        )
    with pytest.raises(CheckmkClientError, match="redirects"):
        await transport.query(
            ReadOnlyQuery(operation="checkmk.problem_services.list"),
            timeout_seconds=2,
            max_response_bytes=65_536,
        )

    mismatch = CheckmkReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"value": [_service_row("other-host", "CPU", 1)]},
            )
        ),
    )
    with pytest.raises(CheckmkClientError, match="another host"):
        await mismatch.query(
            ReadOnlyQuery(
                operation="checkmk.host.problem_services",
                parameters={"host_name": "db-01"},
            ),
            timeout_seconds=2,
            max_response_bytes=65_536,
        )


def test_capabilities_are_explicitly_read_only_and_query_bounded() -> None:
    settings = _settings()
    payload = capabilities(
        _connector_policy(settings),
        _budget_limits(settings),
        backend_role=settings.checkmk_backend_role,
    )
    assert payload["mode"] == "read_only"
    assert payload["backend"]["writeToolsRegistered"] is False
    assert payload["backend"]["arbitraryLivestatusQueriesAllowed"] is False
    assert payload["backend"]["unstableApiAllowed"] is False
    assert payload["safety"]["pluginOutputReturned"] is False
    assert payload["safety"]["configurationEndpointsExposed"] is False
    assert payload["queryBudget"]["max_requests"] == settings.checkmk_budget_max_requests
