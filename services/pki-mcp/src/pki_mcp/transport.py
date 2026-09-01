from __future__ import annotations

import asyncio
from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings
from .models import (
    BackendEnvelope,
    CAObservation,
    ExpiringCertificateObservation,
    PKIEventObservation,
    RevocationPublicationObservation,
)
from .runner import PowerShellRunner
from .scripts import ScriptId

_OPERATION_SCRIPTS: dict[str, ScriptId] = {
    "pki.ca.observe": ScriptId.CA,
    "pki.certificate.list_expiring": ScriptId.EXPIRING,
    "pki.revocation_publication.observe": ScriptId.REVOCATION_PUBLICATION,
    "pki.event.list": ScriptId.EVENTS,
}

_MODELS: dict[str, type] = {
    "pki.ca.observe": CAObservation,
    "pki.certificate.list_expiring": ExpiringCertificateObservation,
    "pki.revocation_publication.observe": RevocationPublicationObservation,
    "pki.event.list": PKIEventObservation,
}


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class PKIReadOnlyTransport:
    """Fixed AD CS/JEA adapter with deployment-owned target aliases and no command proxy."""

    def __init__(self, settings: Settings, *, runner: PowerShellRunner | None = None) -> None:
        if not settings.pki_backend_read_only:
            raise ValueError("PKI_BACKEND_READ_ONLY=true is required")
        if not settings.pki_backend_view_ca_database_attested:
            raise ValueError("PKI_BACKEND_VIEW_CA_DATABASE_ATTESTED=true is required")
        self.settings = settings
        self.targets = settings.targets
        self.runner = runner or PowerShellRunner(settings.pki_powershell_executable)

    @property
    def read_only(self) -> bool:
        return (
            self.settings.pki_backend_read_only
            and self.settings.pki_backend_view_ca_database_attested
        )

    def _payload(self, query: ReadOnlyQuery) -> tuple[str, dict[str, Any]]:
        parameters = dict(query.parameters)
        target_id = parameters.pop("target_id", None)
        if not isinstance(target_id, str) or target_id not in self.targets:
            raise PermissionError("PKI target is not in the configured logical target allowlist")
        if query.page.cursor is not None:
            raise ValueError("PKI Observe v1 deliberately exposes no continuation cursor")

        payload: dict[str, Any] = {"limit": query.page.limit}
        if query.operation in {"pki.ca.observe", "pki.revocation_publication.observe"}:
            if query.page.limit != 1 or parameters:
                raise ValueError("single-object PKI observation accepts no extra parameters")
        elif query.operation == "pki.certificate.list_expiring":
            payload["expiryDays"] = _bounded_int(
                parameters.pop("expiry_days", 30),
                "expiry_days",
                1,
                self.settings.pki_max_expiry_days,
            )
        elif query.operation == "pki.event.list":
            level = parameters.pop("level", "error")
            if level not in {"all", "critical", "error", "warning"}:
                raise ValueError("level must be all, critical, error, or warning")
            payload["level"] = level
            payload["lookbackMinutes"] = _bounded_int(
                parameters.pop("lookback_minutes", 60),
                "lookback_minutes",
                1,
                self.settings.pki_max_event_lookback_minutes,
            )
        else:
            raise PermissionError("PKI operation is not implemented by the fixed adapter")

        if parameters:
            raise ValueError("PKI operation received unsupported parameters")
        return target_id, payload

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        try:
            script_id = _OPERATION_SCRIPTS[query.operation]
        except KeyError as exc:
            raise PermissionError("PKI operation is not implemented by the fixed adapter") from exc
        target_id, payload = self._payload(query)
        raw, payload_bytes = await asyncio.to_thread(
            self.runner.run,
            script_id,
            self.targets[target_id],
            payload,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        envelope = BackendEnvelope.model_validate(raw)
        model = _MODELS[query.operation]
        items = [model.model_validate(item).model_dump(mode="json") for item in envelope.items]
        if len(items) > query.page.limit:
            raise ValueError("PKI backend returned more items than requested")
        truncated = envelope.nextCursor is not None
        if envelope.nextCursor not in {None, "truncated"}:
            raise ValueError("PKI backend returned an unsupported continuation marker")
        return ReadOnlyPage(
            items=items,
            next_cursor=None,
            truncated=truncated,
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self.settings.pki_cache_max_age_seconds),
        )
