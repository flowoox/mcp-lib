from typing import Any
from uuid import UUID

import pytest

import mcp_ad.server as server_module
from mcp_ad.client import DirectoryQueryError


@pytest.mark.asyncio
async def test_observe_emits_metadata_without_copying_result_data(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[dict[str, Any]] = []
    monkeypatch.setattr(server_module, "emit_audit_event", events.append)

    response = await server_module._observe(
        operation="ad_find_user",
        actor="automation@example.internal",
        source="n8n",
        reason="diagnose account login",
        correlation_id="f6f912fb-30a8-4f65-a14f-9f8f09d9229c",
        call=lambda: {"directory_result": "not-copied-to-audit-event"},
    )

    assert UUID(response["correlation_id"])
    assert response["result"]["directory_result"] == "not-copied-to-audit-event"
    assert events == [
        {
            "operation": "ad_find_user",
            "phase": "observe",
            "risk": "read_only",
            "correlation_id": "f6f912fb-30a8-4f65-a14f-9f8f09d9229c",
            "actor": "automation@example.internal",
            "source": "n8n",
            "reason": "diagnose account login",
            "changed": False,
            "status": "succeeded",
        }
    ]


@pytest.mark.asyncio
async def test_observe_failure_audits_error_type_not_exception_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[dict[str, Any]] = []
    monkeypatch.setattr(server_module, "emit_audit_event", events.append)

    def fail() -> None:
        raise DirectoryQueryError("private query detail")

    with pytest.raises(RuntimeError, match="private query detail"):
        await server_module._observe(
            operation="ad_observe_domain_policy",
            actor="operator",
            source="test",
            reason="validate policy",
            correlation_id=None,
            call=fail,
        )

    assert events[0]["status"] == "failed"
    assert events[0]["error_type"] == "DirectoryQueryError"
    assert "private query detail" not in repr(events[0])


@pytest.mark.asyncio
async def test_invalid_correlation_id_fails_before_directory_call() -> None:
    called = False

    def call() -> None:
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="must be a UUID"):
        await server_module._observe(
            operation="ad_find_user",
            actor="operator",
            source="test",
            reason="validate request",
            correlation_id="not-a-uuid",
            call=call,
        )
    assert called is False
