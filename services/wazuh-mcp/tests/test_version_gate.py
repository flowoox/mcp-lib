from __future__ import annotations

import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from wazuh_mcp.client import (
    WazuhClientError,
    WazuhIndexerReadOnlyTransport,
    WazuhServerReadOnlyTransport,
)
from wazuh_mcp.config import Settings
from wazuh_mcp.version_gate import (
    VersionGatedWazuhIndexerTransport,
    VersionGatedWazuhServerTransport,
    WazuhRuntimeVersionGate,
    enforce_wazuh_security_floor,
)


def _settings() -> Settings:
    return Settings(
        wazuh_server_api_base_url="https://manager.example:55000",
        wazuh_server_username="svc-mcp",
        wazuh_server_password="server-secret",
        wazuh_server_backend_read_only=True,
        wazuh_server_backend_role="readonly",
        wazuh_indexer_api_base_url="https://indexer.example:9200",
        wazuh_indexer_username="svc-indexer",
        wazuh_indexer_password="indexer-secret",
        wazuh_indexer_backend_read_only=True,
        wazuh_indexer_backend_role="mcp_wazuh_observer",
    )


def _query(operation: str, *, parameters: dict[str, object] | None = None) -> ReadOnlyQuery:
    return ReadOnlyQuery(
        operation=operation,
        parameters=parameters or {},
        page=PageRequest(limit=1),
        aggregated=True,
    )


def _server_handler(version: object, *, called: list[str] | None = None) -> httpx.MockTransport:
    jwt = "header.payload.signature-1234567890"

    def handler(request: httpx.Request) -> httpx.Response:
        if called is not None:
            called.append(request.url.path)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text=jwt)
        if request.url.path == "/":
            data: dict[str, object] = {
                "title": "Wazuh API REST",
                "revision": "security-floor-test",
            }
            if version is not None:
                data["api_version"] = version
            return httpx.Response(200, json={"data": data, "error": 0})
        if request.url.path == "/agents/summary":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "status": {
                            "active": 1,
                            "disconnected": 0,
                            "pending": 0,
                            "never_connected": 0,
                        }
                    },
                    "error": 0,
                },
            )
        raise AssertionError(f"unexpected Wazuh server path: {request.url.path}")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_security_floor_accepts_4_14_7_and_wrapped_api_info() -> None:
    raw = WazuhServerReadOnlyTransport(_settings(), transport=_server_handler("4.14.7"))
    gate = WazuhRuntimeVersionGate(raw)
    transport = VersionGatedWazuhServerTransport(raw, gate)

    page = await transport.query(
        _query("wazuh.api.info"),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )

    assert page.items == [
        {
            "title": "Wazuh API REST",
            "api_version": "4.14.7",
            "revision": "security-floor-test",
        }
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["4.14.6", "4.14.5", "4.14.4"])
async def test_security_floor_rejects_old_manager_before_observe_operation(version: str) -> None:
    called: list[str] = []
    raw = WazuhServerReadOnlyTransport(
        _settings(),
        transport=_server_handler(version, called=called),
    )
    transport = VersionGatedWazuhServerTransport(raw, WazuhRuntimeVersionGate(raw))

    with pytest.raises(WazuhClientError, match="below required security floor 4.14.7"):
        await transport.query(
            _query("wazuh.agents.summary"),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )

    assert "/agents/summary" not in called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version",
    [None, "", "4.14", "4.14.7-rc1", "latest", "v4.14.7.1", 41407],
)
async def test_security_floor_rejects_missing_or_malformed_version(version: object) -> None:
    raw = WazuhServerReadOnlyTransport(_settings(), transport=_server_handler(version))
    transport = VersionGatedWazuhServerTransport(raw, WazuhRuntimeVersionGate(raw))

    with pytest.raises(WazuhClientError, match="missing or malformed"):
        await transport.query(
            _query("wazuh.api.info"),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )


def test_security_floor_allows_newer_semantic_versions() -> None:
    assert enforce_wazuh_security_floor("v4.14.8") == "v4.14.8"
    assert enforce_wazuh_security_floor("5.0.0") == "5.0.0"


@pytest.mark.asyncio
async def test_indexer_observe_is_blocked_before_search_when_manager_is_old() -> None:
    indexer_called = False

    def indexer_handler(request: httpx.Request) -> httpx.Response:
        nonlocal indexer_called
        indexer_called = True
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "timed_out": False,
                    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
                    "aggregations": {"by_level": {"buckets": []}},
                }
            ).encode(),
        )

    raw_server = WazuhServerReadOnlyTransport(
        _settings(),
        transport=_server_handler("4.14.6"),
    )
    transport = VersionGatedWazuhIndexerTransport(
        WazuhIndexerReadOnlyTransport(
            _settings(),
            transport=httpx.MockTransport(indexer_handler),
        ),
        WazuhRuntimeVersionGate(raw_server),
    )

    with pytest.raises(WazuhClientError, match="below required security floor"):
        await transport.query(
            _query(
                "wazuh.alerts.summary",
                parameters={"window_minutes": 60, "minimum_rule_level": 8},
            ),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )

    assert indexer_called is False


@pytest.mark.asyncio
async def test_successful_attestation_is_cached_across_server_observations() -> None:
    called: list[str] = []
    raw = WazuhServerReadOnlyTransport(
        _settings(),
        transport=_server_handler("4.14.7", called=called),
    )
    transport = VersionGatedWazuhServerTransport(raw, WazuhRuntimeVersionGate(raw))

    await transport.query(
        _query("wazuh.agents.summary"),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    await transport.query(
        _query("wazuh.agents.summary"),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )

    assert called.count("/") == 1
    assert called.count("/security/user/authenticate") == 1
    assert called.count("/agents/summary") == 2
