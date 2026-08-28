from __future__ import annotations

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from n8n_mcp.client import N8nClientError, N8nReadOnlyTransport
from n8n_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "n8n_api_base_url": "https://n8n.example.test/api/v1",
        "n8n_api_key": "super-secret-api-key",
        "n8n_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_workflow_query_is_get_only_key_header_and_safe_projection() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/workflows"
        assert request.headers["X-N8N-API-KEY"] == "super-secret-api-key"
        assert request.url.params["limit"] == "2"
        assert request.url.params["cursor"] == "cursor123"
        assert request.url.params["active"] == "true"
        assert "projectId" not in request.url.params
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "wfA123",
                        "name": "Employee entry",
                        "active": True,
                        "isArchived": False,
                        "createdAt": "2026-08-01T10:00:00.000Z",
                        "updatedAt": "2026-08-27T10:00:00.000Z",
                        "tags": [{"id": "tag1", "name": "onboarding"}],
                        "nodes": [{"parameters": {"password": "must-not-leak"}}],
                        "connections": {"x": "must-not-leak"},
                        "settings": {"executionOrder": "v1"},
                        "staticData": {"secret": "must-not-leak"},
                    },
                    {
                        "id": "wfB456",
                        "name": "Inventory",
                        "active": True,
                        "isArchived": False,
                    },
                ],
                "nextCursor": "next456",
            },
        )

    client = N8nReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(
            operation="n8n.workflows.list",
            parameters={"active": True},
            page=PageRequest(limit=2, cursor="cursor123"),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )

    assert page.next_cursor == "next456"
    assert page.truncated is True
    assert page.items[0] == {
        "workflow_id": "wfA123",
        "name": "Employee entry",
        "active": True,
        "archived": False,
        "created_at": "2026-08-01T10:00:00.000Z",
        "updated_at": "2026-08-27T10:00:00.000Z",
        "tags": [{"tag_id": "tag1", "name": "onboarding"}],
    }
    assert "nodes" not in page.items[0]


@pytest.mark.asyncio
async def test_execution_list_forces_no_data_and_exact_workflow_scope() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/executions"
        assert request.url.params["includeData"] == "false"
        assert request.url.params["workflowId"] == "wfA123"
        assert request.url.params["status"] == "error"
        assert "projectId" not in request.url.params
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "12345",
                        "workflowId": "wfA123",
                        "status": "error",
                        "mode": "webhook",
                        "startedAt": "2026-08-28T06:00:00.000Z",
                        "stoppedAt": "2026-08-28T06:00:01.000Z",
                        "finished": True,
                        "data": {"resultData": {"error": {"message": "secret payload"}}},
                        "workflowData": {"nodes": ["must-not-leak"]},
                    }
                ],
                "nextCursor": None,
            },
        )

    client = N8nReadOnlyTransport(
        _settings(n8n_allowed_workflow_ids="wfA123"),
        transport=httpx.MockTransport(handler),
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="n8n.executions.list",
            parameters={"workflow_id": "wfA123", "status": "error"},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )

    assert page.items == [
        {
            "execution_id": "12345",
            "workflow_id": "wfA123",
            "status": "error",
            "mode": "webhook",
            "started_at": "2026-08-28T06:00:00.000Z",
            "stopped_at": "2026-08-28T06:00:01.000Z",
            "wait_till": "",
            "retry_of": "",
            "retry_success_id": "",
            "finished": True,
        }
    ]
    assert "data" not in page.items[0]


@pytest.mark.asyncio
async def test_allowlist_requires_workflow_scope_before_execution_list_dispatch() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("unscoped execution list must not reach n8n")

    client = N8nReadOnlyTransport(
        _settings(n8n_allowed_workflow_ids="wfA123"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PermissionError, match="workflow_id is required"):
        await client.query(
            ReadOnlyQuery(operation="n8n.executions.list", page=PageRequest(limit=10)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )


@pytest.mark.asyncio
async def test_exact_execution_is_safe_and_verified_against_expected_workflow() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/executions/987"
        assert request.url.params["includeData"] == "false"
        return httpx.Response(
            200,
            json={
                "id": "987",
                "workflowId": "wfA123",
                "status": "success",
                "mode": "trigger",
                "finished": True,
                "data": {"secret": "never return"},
            },
        )

    client = N8nReadOnlyTransport(
        _settings(n8n_allowed_workflow_ids="wfA123"),
        transport=httpx.MockTransport(handler),
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="n8n.executions.get",
            parameters={"execution_id": "987", "workflow_id": "wfA123"},
            page=PageRequest(limit=1),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0]["execution_id"] == "987"
    assert page.items[0]["workflow_id"] == "wfA123"
    assert "data" not in page.items[0]


@pytest.mark.asyncio
async def test_exact_execution_rejects_backend_workflow_mismatch() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"id": "987", "workflowId": "wfB456", "status": "success"},
        )

    client = N8nReadOnlyTransport(
        _settings(n8n_allowed_workflow_ids="wfA123,wfB456"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(N8nClientError, match="expected workflow"):
        await client.query(
            ReadOnlyQuery(
                operation="n8n.executions.get",
                parameters={"execution_id": "987", "workflow_id": "wfA123"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )


@pytest.mark.asyncio
async def test_redirects_and_arbitrary_operations_fail_closed() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example.test"})

    client = N8nReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(N8nClientError, match="redirects"):
        await client.query(
            ReadOnlyQuery(operation="n8n.workflows.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )

    with pytest.raises(PermissionError, match="not implemented"):
        await client.query(
            ReadOnlyQuery(operation="n8n.workflows.delete", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
