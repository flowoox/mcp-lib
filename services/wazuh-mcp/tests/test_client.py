from __future__ import annotations

import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from wazuh_mcp.client import WazuhIndexerReadOnlyTransport, WazuhServerReadOnlyTransport
from wazuh_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "wazuh_server_api_base_url": "https://manager.example:55000",
        "wazuh_server_username": "svc-mcp",
        "wazuh_server_password": "server-secret",
        "wazuh_server_backend_read_only": True,
        "wazuh_server_backend_role": "readonly",
        "wazuh_indexer_api_base_url": "https://indexer.example:9200",
        "wazuh_indexer_username": "svc-indexer",
        "wazuh_indexer_password": "indexer-secret",
        "wazuh_indexer_backend_read_only": True,
        "wazuh_indexer_backend_role": "mcp_wazuh_observer",
    }
    values.update(overrides)
    return Settings(**values)


def _query(
    operation: str,
    *,
    parameters: dict[str, object] | None = None,
    limit: int = 25,
) -> ReadOnlyQuery:
    return ReadOnlyQuery(
        operation=operation,
        parameters=parameters or {},
        page=PageRequest(limit=limit),
        aggregated=True,
    )


def test_server_transport_fails_closed_without_readonly_role() -> None:
    with pytest.raises(ValueError, match="readonly"):
        WazuhServerReadOnlyTransport(
            _settings(wazuh_server_backend_role="administrator"),
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        )


def test_indexer_transport_fails_closed_without_read_role_attestation() -> None:
    with pytest.raises(ValueError, match="read role"):
        WazuhIndexerReadOnlyTransport(
            _settings(wazuh_indexer_backend_role=""),
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        )


@pytest.mark.asyncio
async def test_agent_list_uses_fixed_jwt_auth_get_and_minimized_projection() -> None:
    methods: list[str] = []
    jwt = "header.payload.signature-1234567890"

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path == "/security/user/authenticate":
            assert request.method == "POST"
            assert request.url.params["raw"] == "true"
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, text=jwt)
        assert request.method == "GET"
        assert request.url.path == "/agents"
        assert request.headers["authorization"] == f"Bearer {jwt}"
        assert request.url.params["limit"] == "1"
        assert request.url.params["offset"] == "0"
        assert "q" not in request.url.params
        assert "search" not in request.url.params
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": "001",
                            "name": "endpoint-01",
                            "status": "active",
                            "ip": "10.0.0.10",
                            "registerIP": "10.0.0.10",
                            "group": ["secret-team"],
                            "os": {
                                "name": "Microsoft Windows 11 Pro",
                                "platform": "windows",
                                "version": "10.0.26100",
                            },
                            "version": "Wazuh v4.14.7",
                            "node_name": "node01",
                            "lastKeepAlive": "2026-09-01T07:59:00Z",
                            "group_config_status": "synced",
                        }
                    ],
                    "total_affected_items": 1,
                    "failed_items": [],
                    "total_failed_items": 0,
                },
                "error": 0,
            },
        )

    transport = WazuhServerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await transport.query(
        _query("wazuh.agents.list", limit=1),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    rendered = json.dumps(page.items)
    assert methods == ["POST", "GET"]
    assert page.items[0]["agent_id"] == "001"
    assert page.items[0]["status"] == "active"
    assert "10.0.0.10" not in rendered
    assert "secret-team" not in rendered


@pytest.mark.asyncio
async def test_alert_summary_generates_aggregation_only_indexer_search() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/wazuh-alerts*/_search"
        assert request.headers["authorization"].startswith("Basic ")
        body = json.loads(request.content)
        captured.update(body)
        assert body["size"] == 0
        assert body["_source"] is False
        assert body["track_total_hits"] is True
        filters = body["query"]["bool"]["filter"]
        assert filters[0]["range"]["timestamp"]["gte"] == "now-60m"
        assert filters[1]["range"]["rule.level"]["gte"] == 8
        return httpx.Response(
            200,
            json={
                "timed_out": False,
                "hits": {"total": {"value": 12, "relation": "eq"}, "hits": []},
                "aggregations": {
                    "by_level": {
                        "buckets": [
                            {"key": 8, "doc_count": 9},
                            {"key": 12, "doc_count": 3},
                        ]
                    }
                },
            },
        )

    transport = WazuhIndexerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await transport.query(
        _query(
            "wazuh.alerts.summary",
            parameters={"window_minutes": 60, "minimum_rule_level": 8},
            limit=1,
        ),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    assert captured["size"] == 0
    assert page.items[0]["total"] == 12
    assert page.items[0]["by_level"][1]["level"] == 12


@pytest.mark.asyncio
async def test_vulnerability_summary_returns_only_aggregated_state() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/wazuh-states-vulnerabilities-*/_search"
        body = json.loads(request.content)
        assert body["size"] == 0
        assert body["_source"] is False
        return httpx.Response(
            200,
            json={
                "timed_out": False,
                "hits": {"total": {"value": 25, "relation": "eq"}, "hits": []},
                "aggregations": {
                    "by_severity": {
                        "buckets": [
                            {"key": "Critical", "doc_count": 2},
                            {"key": "High", "doc_count": 7},
                            {"key": "Medium", "doc_count": 16},
                        ]
                    },
                    "max_cvss_base": {"value": 9.8},
                },
            },
        )

    transport = WazuhIndexerReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await transport.query(
        _query("wazuh.vulnerabilities.summary", limit=1),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    assert page.items[0]["total"] == 25
    assert page.items[0]["max_cvss_base"] == 9.8
    assert page.items[0]["by_severity"][0] == {"severity": "Critical", "count": 2}


@pytest.mark.asyncio
async def test_alert_window_and_unknown_operations_are_rejected_before_dispatch() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    transport = WazuhIndexerReadOnlyTransport(
        _settings(wazuh_max_alert_window_minutes=60),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ValueError, match="window_minutes"):
        await transport.query(
            _query("wazuh.alerts.summary", parameters={"window_minutes": 61}, limit=1),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )
    with pytest.raises(PermissionError):
        await transport.query(
            _query("wazuh.indexer.search", limit=1),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )
    assert called is False
