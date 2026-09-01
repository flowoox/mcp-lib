from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from veeam_mcp.client import VeeamReadOnlyTransport
from veeam_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "veeam_api_base_url": "https://veeam.example",
        "veeam_username": "svc-mcp",
        "veeam_password": "secret",
        "veeam_backend_read_only": True,
        "veeam_backend_role": "Backup Viewer",
        "veeam_backend_build": "13.1.1.18",
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


def _auth_response() -> httpx.Response:
    return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})


def test_transport_fails_closed_without_backup_viewer_attestation() -> None:
    with pytest.raises(ValueError, match="Backup Viewer"):
        VeeamReadOnlyTransport(
            _settings(veeam_backend_role="Backup Administrator"),
            transport=httpx.MockTransport(lambda request: _auth_response()),
        )


@pytest.mark.asyncio
async def test_job_states_use_exact_oauth_and_bounded_get() -> None:
    job_id = str(uuid4())
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        if request.url.path == "/api/oauth2/token":
            assert request.method == "POST"
            assert request.headers["x-api-version"] == "1.3-rev2"
            assert b"grant_type=password" in request.content
            return _auth_response()
        assert request.method == "GET"
        assert request.url.path == "/api/v1/jobs/states"
        assert request.headers["authorization"] == "Bearer token"
        assert request.url.params["limit"] == "1"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": job_id,
                        "name": "VM Backup",
                        "type": "HyperVBackup",
                        "status": "Stopped",
                        "lastResult": "Success",
                    }
                ],
                "pagination": {"total": 1, "count": 1, "skip": 0, "limit": 1},
            },
        )

    transport = VeeamReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        _query("veeam.jobs.states", limit=1),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    assert page.items[0]["job_id"] == job_id
    assert page.items[0]["last_result"] == "Success"
    assert methods == ["POST", "GET"]


@pytest.mark.asyncio
async def test_repository_and_session_projection_omit_sensitive_fields() -> None:
    repository_id = str(uuid4())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oauth2/token":
            return _auth_response()
        assert request.url.path.endswith("/repositories/states")
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": repository_id,
                        "name": "Immutable Repo",
                        "type": "LinuxHardened",
                        "hostName": "repo01.corp.example",
                        "path": "/backups/private",
                        "capacityGB": 1000.0,
                        "freeGB": 250.0,
                        "usedSpaceGB": 750.0,
                        "isOnline": True,
                        "isOutOfDate": False,
                    }
                ],
                "pagination": {"total": 1, "count": 1, "skip": 0, "limit": 25},
            },
        )

    transport = VeeamReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await transport.query(
        _query("veeam.repositories.states"),
        timeout_seconds=5,
        max_response_bytes=100_000,
    )
    rendered = json.dumps(page.items)
    assert "repo01.corp.example" not in rendered
    assert "/backups/private" not in rendered
    assert page.items[0]["free_gb"] == 250.0


@pytest.mark.asyncio
async def test_history_cap_and_unknown_operations_are_rejected_before_dispatch() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return _auth_response()

    transport = VeeamReadOnlyTransport(
        _settings(veeam_max_history_hours=24),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ValueError, match="history_hours"):
        await transport.query(
            _query("veeam.restore_points.list", parameters={"history_hours": 25}),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )
    with pytest.raises(PermissionError):
        await transport.query(
            _query("veeam.jobs.start"),
            timeout_seconds=5,
            max_response_bytes=100_000,
        )
    assert called is False
