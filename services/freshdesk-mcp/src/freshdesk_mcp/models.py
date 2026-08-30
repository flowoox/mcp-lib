from __future__ import annotations

from mcp_common.operations import StrictModel
from pydantic import Field


class TicketObservation(StrictModel):
    ticket_id: str = Field(min_length=1, max_length=20)
    subject: str = Field(default="", max_length=256)
    status: int | None = None
    priority: int | None = None
    source: int | None = None
    group_id: str | None = Field(default=None, max_length=20)
    type: str = Field(default="", max_length=128)
    responder_assigned: bool = False
    requester_present: bool = False
    company_scoped: bool = False
    spam: bool | None = None
    first_response_escalated: bool | None = None
    is_escalated: bool | None = None
    created_at: str = Field(default="", max_length=64)
    updated_at: str = Field(default="", max_length=64)
    due_by: str = Field(default="", max_length=64)
    first_response_due_by: str = Field(default="", max_length=64)
    attachment_count: int = Field(default=0, ge=0)


class ConversationObservation(StrictModel):
    conversation_id: str = Field(min_length=1, max_length=20)
    ticket_id: str = Field(min_length=1, max_length=20)
    incoming: bool | None = None
    private: bool | None = None
    source: int | None = None
    created_at: str = Field(default="", max_length=64)
    updated_at: str = Field(default="", max_length=64)
    last_edited_at: str = Field(default="", max_length=64)
    has_body: bool = False
    body_characters: int = Field(default=0, ge=0)
    attachment_count: int = Field(default=0, ge=0)


class ConversationSummary(StrictModel):
    total: int = Field(ge=0)
    incoming: int = Field(ge=0)
    outgoing: int = Field(ge=0)
    private: int = Field(ge=0)
    with_attachments: int = Field(ge=0)
