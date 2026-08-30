from __future__ import annotations

import base64

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from freshdesk_mcp.client import (
    FreshdeskClientError,
    FreshdeskRateLimitError,
    FreshdeskReadOnlyTransport,
)
from freshdesk_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "freshdesk_api_base_url": "https://helpdesk.example.test",
        "freshdesk_api_key": "super-secret-key",
        "freshdesk_backend_read_only": True,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_ticket_list_is_get_only_bounded_and_redacts_sensitive_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v2/tickets"
        expected = base64.b64encode(b"super-secret-key:X").decode()
        assert request.headers["Authorization"] == f"Basic {expected}"
        assert request.url.params["per_page"] == "2"
        assert request.url.params["page"] == "1"
        assert request.url.params["filter"] == "new_and_my_open"
        assert request.url.params["updated_since"] == "2026-08-01T00:00:00Z"
        assert "include" not in request.url.params
        return httpx.Response(
            200,
            headers={
                "Link": '<https://helpdesk.example.test/api/v2/tickets?page=2&per_page=2>; rel="next"'
            },
            json=[
                {
                    "id": 123,
                    "subject": "VPN issue",
                    "status": 2,
                    "priority": 3,
                    "source": 2,
                    "group_id": 10,
                    "type": "Incident",
                    "requester_id": 5001,
                    "responder_id": 7001,
                    "company_id": 9001,
                    "requester": {"name": "Alice", "email": "alice@example.test"},
                    "description": "must-not-leak",
                    "description_text": "must-not-leak",
                    "cc_emails": ["secret@example.test"],
                    "fr_escalated": False,
                    "is_escalated": True,
                    "spam": False,
                    "attachments": [{"name": "secret.txt", "attachment_url": "https://secret"}],
                    "custom_fields": {"secret": "value"},
                }
            ],
        )

    client = FreshdeskReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(
            operation="freshdesk.tickets.list",
            parameters={
                "filter": "new_and_my_open",
                "updated_since": "2026-08-01T00:00:00Z",
            },
            page=PageRequest(limit=2),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )

    assert page.next_cursor == "page:2"
    projected = page.items[0]
    assert projected["ticket_id"] == "123"
    assert projected["subject"] == "VPN issue"
    assert projected["responder_assigned"] is True
    assert projected["requester_present"] is True
    assert projected["company_scoped"] is True
    assert projected["attachment_count"] == 1
    for forbidden in (
        "requester_id",
        "responder_id",
        "company_id",
        "requester",
        "description",
        "description_text",
        "cc_emails",
        "attachments",
        "custom_fields",
    ):
        assert forbidden not in projected


@pytest.mark.asyncio
async def test_ticket_get_redacts_description() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v2/tickets/123"
        return httpx.Response(
            200,
            json={
                "id": 123,
                "subject": "Storage alert",
                "description": "sensitive body",
                "requester_id": 88,
                "responder_id": None,
                "status": 2,
            },
        )

    client = FreshdeskReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(
            operation="freshdesk.tickets.get",
            parameters={"ticket_id": "123"},
            page=PageRequest(limit=1),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    assert page.items[0]["ticket_id"] == "123"
    assert page.items[0]["requester_present"] is True
    assert "description" not in page.items[0]


@pytest.mark.asyncio
async def test_conversations_return_metadata_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v2/tickets/123/conversations"
        assert request.url.params["page"] == "2"
        return httpx.Response(
            200,
            json=[
                {
                    "id": 999,
                    "ticket_id": 123,
                    "incoming": False,
                    "private": True,
                    "source": 2,
                    "body_text": "very private message",
                    "body": "<p>very private message</p>",
                    "structured_body": {"secret": "must-not-leak"},
                    "user_id": 42,
                    "from_email": "agent@example.test",
                    "to_emails": ["requester@example.test"],
                    "support_email": "support@example.test",
                    "created_at": "2026-08-10T10:00:00Z",
                    "updated_at": "2026-08-10T10:01:00Z",
                    "attachments": [{"name": "private.pdf", "attachment_url": "https://secret"}],
                }
            ],
        )

    client = FreshdeskReadOnlyTransport(_settings(), transport=httpx.MockTransport(handler))
    page = await client.query(
        ReadOnlyQuery(
            operation="freshdesk.tickets.conversations",
            parameters={"ticket_id": "123"},
            page=PageRequest(limit=10, cursor="page:2"),
        ),
        timeout_seconds=2,
        max_response_bytes=100_000,
    )
    projected = page.items[0]
    assert projected["conversation_id"] == "999"
    assert projected["body_characters"] == 20
    assert projected["attachment_count"] == 1
    for forbidden in (
        "body",
        "body_text",
        "structured_body",
        "user_id",
        "from_email",
        "to_emails",
        "support_email",
        "attachments",
    ):
        assert forbidden not in projected


@pytest.mark.asyncio
async def test_rejects_generic_search_cross_origin_pagination_and_deep_pages() -> None:
    client = FreshdeskReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Link": '<https://evil.test/api/v2/tickets?page=2>; rel="next"'},
                json=[],
            )
        ),
    )
    with pytest.raises(ValueError, match="unsupported parameters"):
        await client.query(
            ReadOnlyQuery(
                operation="freshdesk.tickets.list",
                parameters={"query": 'status:2 AND email:"secret@example.test"'},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
    with pytest.raises(FreshdeskClientError, match="cross-origin"):
        await client.query(
            ReadOnlyQuery(operation="freshdesk.tickets.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
    capped = FreshdeskReadOnlyTransport(
        _settings(freshdesk_max_page_number=50),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[])),
    )
    with pytest.raises(ValueError, match="page-number limit"):
        await capped.query(
            ReadOnlyQuery(
                operation="freshdesk.tickets.list",
                page=PageRequest(limit=1, cursor="page:51"),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )


@pytest.mark.asyncio
async def test_redirect_byte_limit_invalid_date_and_rate_limit_fail_closed() -> None:
    redirecting = FreshdeskReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"Location": "https://evil.test"})
        ),
    )
    with pytest.raises(FreshdeskClientError, match="redirects"):
        await redirecting.query(
            ReadOnlyQuery(operation="freshdesk.tickets.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )

    oversized = FreshdeskReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"[" + b'"' + b"a" * 200 + b'"' + b"]")
        ),
    )
    with pytest.raises(FreshdeskClientError, match="byte limit"):
        await oversized.query(
            ReadOnlyQuery(operation="freshdesk.tickets.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=32,
        )

    client = FreshdeskReadOnlyTransport(
        _settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[])),
    )
    with pytest.raises(ValueError, match="ISO date"):
        await client.query(
            ReadOnlyQuery(
                operation="freshdesk.tickets.list",
                parameters={"updated_since": "not-a-date"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )

    calls = 0

    def limited(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": "34"}, json={"error": "rate limit"})

    rate_limited = FreshdeskReadOnlyTransport(_settings(), transport=httpx.MockTransport(limited))
    with pytest.raises(FreshdeskRateLimitError) as exc:
        await rate_limited.query(
            ReadOnlyQuery(operation="freshdesk.tickets.list", page=PageRequest(limit=1)),
            timeout_seconds=2,
            max_response_bytes=100_000,
        )
    assert exc.value.retry_after_seconds == 34
    assert calls == 1
