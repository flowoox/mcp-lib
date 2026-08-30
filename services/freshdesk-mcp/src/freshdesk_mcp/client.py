from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import ConversationObservation, TicketObservation

_ID_RE = re.compile(r"^[0-9]{1,20}$")
_TICKET_FILTERS = frozenset({"new_and_my_open", "watching", "spam", "deleted"})
_ORDER_FIELDS = frozenset({"created_at", "due_by", "updated_at", "status"})
_ORDER_TYPES = frozenset({"asc", "desc"})


class FreshdeskClientError(RuntimeError):
    """Raised when the fixed Freshdesk adapter rejects or cannot parse a response."""


class FreshdeskRateLimitError(FreshdeskClientError):
    """Raised on Freshdesk HTTP 429 without automatically retrying or amplifying load."""

    def __init__(self, retry_after_seconds: int | None) -> None:
        self.retry_after_seconds = retry_after_seconds
        message = "Freshdesk rate limit reached"
        if retry_after_seconds is not None:
            message += f"; retry after {retry_after_seconds} seconds"
        super().__init__(message)


def _text(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return str(value)[:max_length]


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return None


def _identifier(value: Any, *, field: str) -> str:
    normalized = _text(value, max_length=21).strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError(f"{field} must be a bounded decimal identifier")
    return normalized


def _optional_identifier(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return _identifier(value, field="identifier")


def _attachments_count(value: Any) -> int:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return min(len(value), 10_000)
    return 0


def _project_ticket(row: Mapping[str, Any]) -> dict[str, Any]:
    return TicketObservation(
        ticket_id=_identifier(row.get("id"), field="ticket_id"),
        subject=_text(row.get("subject"), max_length=256),
        status=_integer(row.get("status")),
        priority=_integer(row.get("priority")),
        source=_integer(row.get("source")),
        group_id=_optional_identifier(row.get("group_id")),
        type=_text(row.get("type"), max_length=128),
        responder_assigned=row.get("responder_id") not in {None, ""},
        requester_present=row.get("requester_id") not in {None, ""},
        company_scoped=row.get("company_id") not in {None, ""},
        spam=_boolean(row.get("spam")),
        first_response_escalated=_boolean(row.get("fr_escalated")),
        is_escalated=_boolean(row.get("is_escalated")),
        created_at=_text(row.get("created_at"), max_length=64),
        updated_at=_text(row.get("updated_at"), max_length=64),
        due_by=_text(row.get("due_by"), max_length=64),
        first_response_due_by=_text(row.get("fr_due_by"), max_length=64),
        attachment_count=_attachments_count(row.get("attachments")),
    ).model_dump(mode="json")


def _project_conversation(expected_ticket_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
    returned_ticket_id = _identifier(
        row.get("ticket_id", expected_ticket_id), field="ticket_id"
    )
    if returned_ticket_id != expected_ticket_id:
        raise FreshdeskClientError("Freshdesk returned a conversation for another ticket")
    body_text = row.get("body_text")
    body = body_text if isinstance(body_text, str) else row.get("body")
    body_characters = min(len(body), 10_000_000) if isinstance(body, str) else 0
    return ConversationObservation(
        conversation_id=_identifier(row.get("id"), field="conversation_id"),
        ticket_id=returned_ticket_id,
        incoming=_boolean(row.get("incoming")),
        private=_boolean(row.get("private")),
        source=_integer(row.get("source")),
        created_at=_text(row.get("created_at"), max_length=64),
        updated_at=_text(row.get("updated_at"), max_length=64),
        last_edited_at=_text(row.get("last_edited_at"), max_length=64),
        has_body=body_characters > 0,
        body_characters=body_characters,
        attachment_count=_attachments_count(row.get("attachments")),
    ).model_dump(mode="json")


def _validate_updated_since(value: Any) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise ValueError("updated_since must be a Freshdesk date or timestamp string")
    normalized = value.strip()
    if not 1 <= len(normalized) <= 40 or any(ord(character) < 32 for character in normalized):
        raise ValueError("updated_since must be a bounded Freshdesk date or timestamp")
    try:
        if len(normalized) == 10:
            date.fromisoformat(normalized)
        else:
            datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("updated_since must be an ISO date or timestamp") from exc
    return normalized


class FreshdeskReadOnlyTransport:
    """Freshdesk API v2 adapter with a fixed GET-only observation surface."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.freshdesk_backend_read_only:
            raise ValueError(
                "FRESHDESK_BACKEND_READ_ONLY=true is required for the Freshdesk reader identity"
            )
        if not settings.configured:
            raise ValueError("FRESHDESK_API_BASE_URL and FRESHDESK_API_KEY are required")
        self.settings = settings
        self._transport = transport
        parsed = urlsplit(settings.freshdesk_api_base_url)
        self._origin = (parsed.scheme.lower(), parsed.netloc.lower())

    @property
    def read_only(self) -> bool:
        return self.settings.freshdesk_backend_read_only

    async def _request_json(
        self,
        path: str,
        *,
        params: Sequence[tuple[str, str]] = (),
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int, str | None]:
        if path.startswith("/") or ".." in path:
            raise ValueError("Freshdesk adapter path must be a fixed relative API path")
        api_key = self.settings.freshdesk_api_key.get_secret_value()
        async with httpx.AsyncClient(
            base_url=f"{self.settings.freshdesk_api_base_url}/",
            transport=self._transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            verify=self.settings.freshdesk_tls_verify,
            auth=httpx.BasicAuth(api_key, "X"),
            headers={
                "Accept": "application/json",
                "User-Agent": "flowoox-mcp-freshdesk/0.1",
            },
        ) as client, client.stream("GET", path, params=list(params)) as response:
            if 300 <= response.status_code < 400:
                raise FreshdeskClientError("Freshdesk redirects are not allowed")
            if response.status_code == 429:
                raw_retry = response.headers.get("Retry-After", "").strip()
                retry_after = int(raw_retry) if raw_retry.isdecimal() else None
                raise FreshdeskRateLimitError(retry_after)
            if response.status_code != 200:
                raise FreshdeskClientError(
                    f"Freshdesk GET operation failed with status {response.status_code}"
                )
            link = response.headers.get("Link")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(body):
                    raise FreshdeskClientError(
                        "Freshdesk response exceeded the configured byte limit"
                    )
                body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FreshdeskClientError("Freshdesk returned invalid JSON") from exc
        return payload, len(body), link

    @staticmethod
    def _parameters(query: ReadOnlyQuery, allowed: frozenset[str]) -> dict[str, Any]:
        unexpected = set(query.parameters) - allowed
        if unexpected:
            raise ValueError("Freshdesk operation received unsupported parameters")
        return dict(query.parameters)

    def _page_number(self, cursor: str | None) -> int:
        if cursor is None:
            return 1
        if not cursor.startswith("page:"):
            raise ValueError("unsupported Freshdesk pagination cursor")
        raw = cursor.removeprefix("page:")
        if not raw.isdecimal() or len(raw) > 3:
            raise ValueError("invalid Freshdesk page cursor")
        page = int(raw)
        if not 1 <= page <= self.settings.freshdesk_max_page_number:
            raise ValueError("Freshdesk page cursor exceeds the configured page-number limit")
        return page

    def _next_cursor(
        self,
        link: str | None,
        *,
        expected_path: str,
        current_page: int,
    ) -> str | None:
        if not link:
            return None
        next_url = ""
        for segment in link.split(","):
            if 'rel="next"' not in segment and "rel=next" not in segment:
                continue
            match = re.search(r"<([^>]+)>", segment)
            if match:
                next_url = match.group(1)
                break
        if not next_url:
            return None
        parsed = urlsplit(next_url)
        if (parsed.scheme.lower(), parsed.netloc.lower()) != self._origin:
            raise FreshdeskClientError("Freshdesk returned a cross-origin next-page link")
        if parsed.path != f"/{expected_path}" or parsed.fragment:
            raise FreshdeskClientError("Freshdesk returned an invalid next-page link")
        pages = parse_qs(parsed.query, keep_blank_values=True).get("page", [])
        if len(pages) != 1 or not pages[0].isdecimal() or len(pages[0]) > 3:
            raise FreshdeskClientError("Freshdesk next-page link omitted a valid page number")
        page = int(pages[0])
        if page <= current_page:
            raise FreshdeskClientError("Freshdesk next-page link did not advance pagination")
        if page > self.settings.freshdesk_max_page_number:
            return None
        return f"page:{page}"

    async def _tickets(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(
            query,
            frozenset({"filter", "updated_since", "order_by", "order_type"}),
        )
        page_number = self._page_number(query.page.cursor)
        params: list[tuple[str, str]] = [
            ("per_page", str(query.page.limit)),
            ("page", str(page_number)),
        ]
        ticket_filter = parameters.get("filter")
        if ticket_filter is not None and ticket_filter != "":
            if not isinstance(ticket_filter, str) or ticket_filter not in _TICKET_FILTERS:
                raise ValueError("filter is not in the fixed Freshdesk allowlist")
            params.append(("filter", ticket_filter))
        updated_since = _validate_updated_since(parameters.get("updated_since"))
        if updated_since:
            params.append(("updated_since", updated_since))
        order_by = parameters.get("order_by", "updated_at")
        if not isinstance(order_by, str) or order_by not in _ORDER_FIELDS:
            raise ValueError("order_by is not in the fixed Freshdesk allowlist")
        order_type = parameters.get("order_type", "desc")
        if not isinstance(order_type, str) or order_type not in _ORDER_TYPES:
            raise ValueError("order_type must be asc or desc")
        params.extend((("order_by", order_by), ("order_type", order_type)))

        path = "api/v2/tickets"
        payload, payload_bytes, link = await self._request_json(
            path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if not isinstance(payload, list):
            raise FreshdeskClientError("Freshdesk ticket-list response must be a JSON array")
        if len(payload) > query.page.limit:
            raise FreshdeskClientError("Freshdesk returned more tickets than requested")
        rows = []
        for raw_row in payload:
            if not isinstance(raw_row, Mapping):
                raise FreshdeskClientError("Freshdesk ticket row must be a JSON object")
            rows.append(_project_ticket(raw_row))
        cursor = self._next_cursor(link, expected_path=path, current_page=page_number)
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.freshdesk_cache_max_age_seconds),
        )

    async def _ticket(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"ticket_id"}))
        ticket_id = _identifier(parameters.get("ticket_id"), field="ticket_id")
        payload, payload_bytes, _ = await self._request_json(
            f"api/v2/tickets/{ticket_id}",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if not isinstance(payload, Mapping):
            raise FreshdeskClientError("Freshdesk ticket response must be a JSON object")
        projected = _project_ticket(payload)
        if projected["ticket_id"] != ticket_id:
            raise FreshdeskClientError("Freshdesk returned another ticket than requested")
        return ReadOnlyPage(
            items=[projected],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.freshdesk_cache_max_age_seconds),
        )

    async def _conversations(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        parameters = self._parameters(query, frozenset({"ticket_id"}))
        ticket_id = _identifier(parameters.get("ticket_id"), field="ticket_id")
        page_number = self._page_number(query.page.cursor)
        path = f"api/v2/tickets/{ticket_id}/conversations"
        payload, payload_bytes, link = await self._request_json(
            path,
            params=(
                ("per_page", str(query.page.limit)),
                ("page", str(page_number)),
            ),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if not isinstance(payload, list):
            raise FreshdeskClientError("Freshdesk conversation response must be a JSON array")
        if len(payload) > query.page.limit:
            raise FreshdeskClientError("Freshdesk returned more conversations than requested")
        rows = []
        for raw_row in payload:
            if not isinstance(raw_row, Mapping):
                raise FreshdeskClientError("Freshdesk conversation row must be a JSON object")
            rows.append(_project_conversation(ticket_id, raw_row))
        cursor = self._next_cursor(link, expected_path=path, current_page=page_number)
        return ReadOnlyPage(
            items=rows,
            next_cursor=cursor,
            truncated=cursor is not None,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.freshdesk_cache_max_age_seconds),
        )

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation == "freshdesk.tickets.list":
            return await self._tickets(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "freshdesk.tickets.get":
            return await self._ticket(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        if query.operation == "freshdesk.tickets.conversations":
            return await self._conversations(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        raise PermissionError("Freshdesk operation is not in the fixed read-only transport allowlist")
