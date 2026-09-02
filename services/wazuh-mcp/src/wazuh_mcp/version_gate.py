from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .client import WazuhClientError, WazuhIndexerReadOnlyTransport, WazuhServerReadOnlyTransport
from .models import ApiInfoObservation

WAZUH_SECURITY_FLOOR = (4, 14, 7)
WAZUH_SECURITY_FLOOR_TEXT = "4.14.7"
_VERSION_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _api_info_data(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise WazuhClientError("Wazuh API info response must be a JSON object")

    if "data" not in payload:
        return payload

    error = payload.get("error")
    if error not in {None, 0, "0"}:
        raise WazuhClientError("Wazuh API info returned an application error")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise WazuhClientError("Wazuh API info omitted its data object")
    return data


def _parse_version(value: Any) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise WazuhClientError("Wazuh API version is missing or malformed")
    normalized = value.strip()
    match = _VERSION_RE.fullmatch(normalized)
    if match is None:
        raise WazuhClientError("Wazuh API version is missing or malformed")
    return tuple(int(part) for part in match.groups())


def enforce_wazuh_security_floor(value: Any) -> str:
    parsed = _parse_version(value)
    if parsed < WAZUH_SECURITY_FLOOR:
        rendered = str(value).strip()
        raise WazuhClientError(
            f"Wazuh API version {rendered} is below required security floor "
            f"{WAZUH_SECURITY_FLOOR_TEXT}"
        )
    return str(value).strip()


class WazuhRuntimeVersionGate:
    """Attest the server API version once before any configured Observe backend use."""

    def __init__(self, server: WazuhServerReadOnlyTransport) -> None:
        self._server = server
        self._page: ReadOnlyPage | None = None

    async def attest(
        self,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if self._page is not None:
            return self._page

        payload, payload_bytes = await self._server._request_json(  # noqa: SLF001
            "",
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        data = _api_info_data(payload)
        api_version = enforce_wazuh_security_floor(data.get("api_version"))
        item = ApiInfoObservation(
            title=str(data.get("title") or "")[:64],
            api_version=api_version,
            revision=str(data.get("revision") or "")[:32],
        ).model_dump(mode="json")
        self._page = ReadOnlyPage(
            items=[item],
            payload_bytes=payload_bytes,
            cache_hint=CacheHint(max_age_seconds=self._server.settings.wazuh_cache_max_age_seconds),
        )
        return self._page


class VersionGatedWazuhServerTransport:
    """Server adapter that fails closed below the reviewed Wazuh security floor."""

    def __init__(
        self,
        transport: WazuhServerReadOnlyTransport,
        gate: WazuhRuntimeVersionGate,
    ) -> None:
        self._transport = transport
        self._gate = gate

    @property
    def read_only(self) -> bool:
        return self._transport.read_only

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        attested = await self._gate.attest(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        if query.operation == "wazuh.api.info":
            if query.parameters:
                raise ValueError("Wazuh API info does not accept parameters")
            return attested
        return await self._transport.query(
            query,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )


class VersionGatedWazuhIndexerTransport:
    """Indexer adapter that requires the same patched Wazuh server stack attestation."""

    def __init__(
        self,
        transport: WazuhIndexerReadOnlyTransport,
        gate: WazuhRuntimeVersionGate,
    ) -> None:
        self._transport = transport
        self._gate = gate

    @property
    def read_only(self) -> bool:
        return self._transport.read_only

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        await self._gate.attest(
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return await self._transport.query(
            query,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
