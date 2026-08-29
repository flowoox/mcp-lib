from __future__ import annotations

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from manageengine_mdm_mcp.client import (
    ManageEngineMdmClientError,
    ManageEngineMdmReadOnlyTransport,
)
from manageengine_mdm_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "mdm_api_base_url": "https://mdm.example.test",
        "mdm_api_token": "super-secret-token",
        "mdm_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_device_list_is_get_only_and_redacts_sensitive_inventory() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/mdm/devices"
        assert request.headers["Authorization"] == "Zoho-oauthtoken super-secret-token"
        assert request.url.params["limit"] == "2"
        assert request.url.params["summary"] == "true"
        assert request.url.params["platform"] == "2"
        assert request.url.params["search"] == "client-01"
        return httpx.Response(
            200,
            json={
                "devices": [
                    {
                        "device_id": "9007199254741001",
                        "device_name": "client-01",
                        "platform_type": "android",
                        "platform_type_id": "2",
                        "os_version": "14",
                        "product_name": "Vendor",
                        "model": "Model X",
                        "owned_by": "1",
                        "is_lost_mode_enabled": False,
                        "serial_number": "must-not-leak",
                        "udid": "must-not-leak",
                        "imei": 123456789,
                        "user": {"user_name": "Alice", "user_email": "alice@example.test"},
                        "summary": {
                            "profile_count": "5",
                            "app_count": "10",
                            "doc_count": "1",
                            "group_count": "2",
                        },
                    }
                ],
                "paging": {
                    "next": "https://mdm.example.test/api/v1/mdm/devices?skip-token=abc%3D%3D&limit=2&platform=2"
                },
            },
        )

    client = ManageEngineMdmReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="manageengine_mdm.devices.list",
            parameters={"platform": "android", "search": "client-01"},
            page=PageRequest(limit=2),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )

    assert page.next_cursor == "skip:abc=="
    assert page.items == [
        {
            "device_id": "9007199254741001",
            "device_name": "client-01",
            "platform_type": "android",
            "platform_type_id": "2",
            "os_version": "14",
            "product_name": "Vendor",
            "model": "Model X",
            "owned_by": "1",
            "lost_mode_enabled": False,
            "profile_count": 5,
            "app_count": 10,
            "document_count": 1,
            "group_count": 2,
        }
    ]
    projected = page.items[0]
    assert "serial_number" not in projected
    assert "udid" not in projected
    assert "imei" not in projected
    assert "user" not in projected


@pytest.mark.asyncio
async def test_onprem_auth_and_customer_header_are_deployment_owned() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "api-key"
        assert request.headers["X-CUSTOMER"] == "12345"
        return httpx.Response(200, json={"devices": []})

    client = ManageEngineMdmReadOnlyTransport(
        _settings(mdm_auth_mode="onprem_api_key", mdm_api_token="api-key", mdm_customer_id="12345"),
        transport=httpx.MockTransport(handler),
    )
    await client.query(
        ReadOnlyQuery(operation="manageengine_mdm.devices.list", page=PageRequest(limit=1)),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )


@pytest.mark.asyncio
async def test_scan_status_does_not_return_kb_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/mdm/devices/123/actions/scan"
        return httpx.Response(
            200,
            json={
                "status_code": 0,
                "status_description": "Command failed",
                "kb_url": "https://internal.example.test/secret-path",
            },
        )

    client = ManageEngineMdmReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="manageengine_mdm.devices.scan_status",
            parameters={"device_id": "123"},
            page=PageRequest(limit=1),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0] == {
        "device_id": "123",
        "status_code": 0,
        "status_description": "Command failed",
        "has_kb_url": True,
    }


@pytest.mark.asyncio
async def test_command_history_is_bounded_and_redacts_initiator_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/mdm/devices/123/commandhistory"
        assert request.url.params["days"] == "7"
        assert request.url.params["offset"] == "20"
        return httpx.Response(
            200,
            json={
                "commands": [
                    {
                        "device_id": "123",
                        "command_history_id": 99,
                        "command_name": "AssetScan",
                        "command_status": 2,
                        "managed_status": 2,
                        "added_time": "123456",
                        "added_by": 42,
                        "added_by_name": "admin",
                        "remarks": "private remark",
                        "command_life": [
                            {
                                "status_code": 2,
                                "status_description": "Command Success",
                                "updated_time": 123999,
                                "added_by_name": "admin",
                                "remarks": "private",
                            }
                        ],
                    }
                ]
            },
        )

    client = ManageEngineMdmReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    page = await client.query(
        ReadOnlyQuery(
            operation="manageengine_mdm.devices.command_history",
            parameters={"device_id": "123", "days": 7},
            page=PageRequest(limit=10, cursor="offset:20"),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0]["command_name"] == "AssetScan"
    assert page.items[0]["latest_status_description"] == "Command Success"
    assert "added_by" not in page.items[0]
    assert "added_by_name" not in page.items[0]
    assert "remarks" not in page.items[0]


@pytest.mark.asyncio
async def test_rejects_unsupported_params_days_and_redirects() -> None:
    client = ManageEngineMdmReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"location": "https://evil.test"})),
    )
    with pytest.raises(ValueError, match="unsupported parameters"):
        await client.query(
            ReadOnlyQuery(
                operation="manageengine_mdm.devices.list",
                parameters={"serial_number": "secret"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
    with pytest.raises(ValueError, match="between 1 and 30"):
        await client.query(
            ReadOnlyQuery(
                operation="manageengine_mdm.devices.command_history",
                parameters={"device_id": "123", "days": 365},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
    with pytest.raises(ManageEngineMdmClientError, match="redirects"):
        await client.query(
            ReadOnlyQuery(operation="manageengine_mdm.devices.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )


@pytest.mark.asyncio
async def test_response_byte_limit_fails_before_json_projection() -> None:
    client = ManageEngineMdmReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b'{' + b'"x":"' + b'a' * 200 + b'"}')),
    )
    with pytest.raises(ManageEngineMdmClientError, match="byte limit"):
        await client.query(
            ReadOnlyQuery(operation="manageengine_mdm.devices.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=32,
        )
