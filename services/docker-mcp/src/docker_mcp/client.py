from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from typing import Any, Literal

import httpx
from mcp_common.operations import StrictModel
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery
from pydantic import Field, field_validator

from .config import Settings, normalize_docker_host
from .models import DockerContainerSummary, DockerEventSummary, DockerLogLine, DockerSystemSummary

_CONTAINER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[-_]?key|authorization)\b(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\S{1,48}$")
_SAFE_EVENT_ATTRIBUTES = frozenset({"name", "image", "container", "exitCode", "signal"})
_EVENT_TYPES = frozenset({"container", "image", "volume", "network", "daemon"})


class DockerClientError(RuntimeError):
    pass


class ContainerListParameters(StrictModel):
    include_stopped: bool = False


class ContainerLogParameters(StrictModel):
    container_id: str = Field(min_length=1, max_length=128)
    since_seconds_ago: int = Field(default=300, ge=1, le=86_400)

    @field_validator("container_id")
    @classmethod
    def validate_container_id(cls, value: str) -> str:
        normalized = value.strip()
        if not _CONTAINER_ID_RE.fullmatch(normalized):
            raise ValueError("container_id must be a Docker ID or simple container name")
        return normalized


class EventListParameters(StrictModel):
    since_seconds_ago: int = Field(default=60, ge=1, le=3_600)
    object_types: list[Literal["container", "image", "volume", "network", "daemon"]] = Field(
        default_factory=lambda: ["container"],
        min_length=1,
        max_length=5,
    )


class DockerApiTransport:
    """Fixed GET-only adapter for a narrow subset of the Docker Engine API."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.docker_backend_read_only:
            raise ValueError(
                "DOCKER_BACKEND_READ_ONLY=true is required to attest a read-only backend identity"
            )
        endpoint = normalize_docker_host(settings.docker_host)
        if endpoint.kind == "unix" and not settings.docker_allow_direct_socket:
            raise ValueError(
                "direct Docker sockets are disabled; use a read-only authorization proxy or set "
                "DOCKER_ALLOW_DIRECT_SOCKET=true as an explicit privileged override"
            )
        if not settings.docker_tls_verify and not settings.docker_allow_insecure_tls:
            raise ValueError(
                "DOCKER_TLS_VERIFY=false requires DOCKER_ALLOW_INSECURE_TLS=true"
            )

        self.settings = settings
        self.endpoint = endpoint
        self._transport = transport
        if self._transport is None and endpoint.kind == "unix":
            self._transport = httpx.AsyncHTTPTransport(uds=endpoint.socket_path)

    @property
    def read_only(self) -> bool:
        return self.settings.docker_backend_read_only

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "flowoox-mcp-docker/0.1",
        }
        token = self.settings.docker_auth_token.get_secret_value()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _api_path(self, path: str) -> str:
        if not path.startswith("/"):
            raise ValueError("Docker API paths must be absolute")
        return f"/{self.settings.docker_api_version}{path}"

    async def _get_bytes(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> bytes:
        async with httpx.AsyncClient(
            base_url=self.endpoint.base_url,
            headers=self._headers,
            transport=self._transport,
            verify=self.settings.docker_tls_verify,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        ) as client, client.stream("GET", path, params=params) as response:
            if 300 <= response.status_code < 400:
                raise DockerClientError("Docker API redirects are not allowed")
            if response.status_code >= 400:
                raise DockerClientError(
                    f"Docker API GET {path} failed with status {response.status_code}"
                )
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise DockerClientError("Docker API returned invalid Content-Length") from exc
                if declared < 0 or declared > max_response_bytes:
                    raise DockerClientError("Docker API response exceeds the configured byte limit")
            payload = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunk) > max_response_bytes - len(payload):
                    raise DockerClientError("Docker API response exceeds the configured byte limit")
                payload.extend(chunk)
        return bytes(payload)

    async def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> tuple[Any, int]:
        payload = await self._get_bytes(
            path,
            params=params,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        try:
            return json.loads(payload), len(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DockerClientError("Docker API returned invalid JSON") from exc

    @staticmethod
    def _bounded_strings(value: Any, *, limit: int, max_length: int = 200) -> list[str]:
        if not isinstance(value, (list, tuple, set)):
            return []
        return [str(item)[:max_length] for item in list(value)[:limit]]

    @staticmethod
    def _container_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker container list contained a non-object item")
        network_settings = value.get("NetworkSettings")
        networks_value = network_settings.get("Networks") if isinstance(network_settings, dict) else {}
        network_names = (
            sorted(str(name)[:200] for name in networks_value)
            if isinstance(networks_value, dict)
            else []
        )

        mounts: list[dict[str, str]] = []
        raw_mounts = value.get("Mounts")
        if isinstance(raw_mounts, list):
            for mount in raw_mounts[:16]:
                if not isinstance(mount, dict):
                    continue
                mounts.append(
                    {
                        "type": str(mount.get("Type") or "")[:40],
                        "name": str(mount.get("Name") or "")[:200],
                        "destination": str(mount.get("Destination") or "")[:500],
                    }
                )

        ports: list[dict[str, Any]] = []
        raw_ports = value.get("Ports")
        if isinstance(raw_ports, list):
            for port in raw_ports[:32]:
                if not isinstance(port, dict):
                    continue
                ports.append(
                    {
                        "privatePort": port.get("PrivatePort"),
                        "publicPort": port.get("PublicPort"),
                        "type": str(port.get("Type") or "")[:10],
                        "published": port.get("PublicPort") is not None,
                    }
                )

        names = DockerApiTransport._bounded_strings(value.get("Names"), limit=8)
        summary = DockerContainerSummary.model_validate({
            "id": str(value.get("Id") or "")[:128],
            "names": names,
            "image": str(value.get("Image") or "")[:500],
            "imageId": str(value.get("ImageID") or "")[:200],
            "created": value.get("Created"),
            "state": str(value.get("State") or "")[:50],
            "status": str(value.get("Status") or "")[:300],
            "networks": network_names[:16],
            "mounts": mounts,
            "ports": ports,
            "nestedTruncated": {
                "names": isinstance(value.get("Names"), list) and len(value["Names"]) > 8,
                "networks": len(network_names) > 16,
                "mounts": isinstance(raw_mounts, list) and len(raw_mounts) > 16,
                "ports": isinstance(raw_ports, list) and len(raw_ports) > 32,
            },
        })
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _system_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker info response must be an object")
        swarm = value.get("Swarm") if isinstance(value.get("Swarm"), dict) else {}
        summary = DockerSystemSummary.model_validate({
            "serverVersion": str(value.get("ServerVersion") or "")[:100],
            "operatingSystem": str(value.get("OperatingSystem") or "")[:200],
            "osType": str(value.get("OSType") or "")[:50],
            "architecture": str(value.get("Architecture") or "")[:50],
            "driver": str(value.get("Driver") or "")[:100],
            "containers": value.get("Containers"),
            "containersRunning": value.get("ContainersRunning"),
            "containersPaused": value.get("ContainersPaused"),
            "containersStopped": value.get("ContainersStopped"),
            "images": value.get("Images"),
            "cpuCount": value.get("NCPU"),
            "memoryBytes": value.get("MemTotal"),
            "swarm": {
                "localNodeState": str(swarm.get("LocalNodeState") or "")[:50],
                "controlAvailable": bool(swarm.get("ControlAvailable", False)),
            },
        })
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _demux_log_payload(payload: bytes) -> list[tuple[str, bytes]]:
        if len(payload) < 8:
            return [("unknown", payload)] if payload else []
        frames: list[tuple[str, bytes]] = []
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < 8:
                return [("unknown", payload)]
            header = payload[offset : offset + 8]
            if header[0] not in {0, 1, 2} or header[1:4] != b"\x00\x00\x00":
                return [("unknown", payload)]
            size = int.from_bytes(header[4:8], byteorder="big")
            end = offset + 8 + size
            if size < 0 or end > len(payload):
                return [("unknown", payload)]
            stream = {1: "stdout", 2: "stderr"}.get(header[0], "unknown")
            frames.append((stream, payload[offset + 8 : end]))
            offset = end
        return frames

    def _redact_log_message(self, value: str) -> str:
        cleaned = "".join(character if character == "\t" or ord(character) >= 32 else "�" for character in value)
        cleaned = _BEARER_RE.sub("Bearer [REDACTED]", cleaned)
        cleaned = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", cleaned)
        return cleaned[: self.settings.docker_max_log_line_chars]

    def _log_lines(self, payload: bytes, *, limit: int) -> list[dict[str, Any]]:
        lines: list[dict[str, Any]] = []
        for stream, frame in self._demux_log_payload(payload):
            text = frame.decode("utf-8", errors="replace")
            for raw_line in text.splitlines():
                timestamp: str | None = None
                message = raw_line
                first, separator, remainder = raw_line.partition(" ")
                if separator and _TIMESTAMP_RE.fullmatch(first):
                    timestamp = first[:64]
                    message = remainder
                line = DockerLogLine.model_validate({
                    "timestamp": timestamp,
                    "stream": stream,
                    "message": self._redact_log_message(message),
                })
                lines.append(line.model_dump(mode="json", by_alias=True))
                if len(lines) >= limit:
                    return lines
        return lines

    @staticmethod
    def _event_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker event stream contained a non-object item")
        actor = value.get("Actor") if isinstance(value.get("Actor"), dict) else {}
        raw_attributes = actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
        attributes = {
            str(key)[:40]: str(raw_attributes[key])[:300]
            for key in _SAFE_EVENT_ATTRIBUTES
            if key in raw_attributes
        }
        summary = DockerEventSummary.model_validate({
            "type": str(value.get("Type") or value.get("type") or "")[:40],
            "action": str(value.get("Action") or value.get("status") or "")[:80],
            "actorId": str(actor.get("ID") or value.get("id") or "")[:128],
            "scope": str(value.get("scope") or value.get("Scope") or "")[:40],
            "time": value.get("time"),
            "timeNano": value.get("timeNano"),
            "attributes": attributes,
        })
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _event_items(payload: bytes, *, limit: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for raw_line in payload.splitlines():
            if not raw_line.strip():
                continue
            try:
                value = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DockerClientError("Docker event stream returned invalid JSON") from exc
            items.append(DockerApiTransport._event_summary(value))
            if len(items) >= limit:
                break
        return items

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.page.cursor is not None:
            raise ValueError("the current Docker Engine inventory slice has no stable cursor")

        if query.operation == "docker.system.ping":
            if query.parameters:
                raise ValueError("docker.system.ping does not accept parameters")
            payload = await self._get_bytes(
                "/_ping",
                params=None,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            ok = payload.strip() == b"OK"
            return ReadOnlyPage(
                items=[{"ok": ok}],
                payload_bytes=len(payload),
                cache_hint=CacheHint(max_age_seconds=2),
            )

        if query.operation == "docker.system.info":
            if query.parameters:
                raise ValueError("docker.system.info does not accept parameters")
            payload, size = await self._get_json(
                self._api_path("/info"),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            return ReadOnlyPage(
                items=[self._system_summary(payload)],
                payload_bytes=size,
                cache_hint=CacheHint(max_age_seconds=5),
            )

        if query.operation == "docker.containers.list":
            parameters = ContainerListParameters.model_validate(query.parameters)
            payload, size = await self._get_json(
                self._api_path("/containers/json"),
                params={
                    "all": "true" if parameters.include_stopped else "false",
                    "limit": str(query.page.limit),
                },
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            if not isinstance(payload, list):
                raise DockerClientError("Docker container list response must be an array")
            items = [self._container_summary(item) for item in payload]
            return ReadOnlyPage(
                items=items,
                payload_bytes=size,
                truncated=len(items) == query.page.limit,
                cache_hint=CacheHint(max_age_seconds=5),
            )

        if query.operation == "docker.containers.logs":
            parameters = ContainerLogParameters.model_validate(query.parameters)
            if parameters.since_seconds_ago > self.settings.docker_max_log_window_seconds:
                raise ValueError(
                    "requested log window exceeds DOCKER_MAX_LOG_WINDOW_SECONDS"
                )
            now = int(time.time())
            payload = await self._get_bytes(
                self._api_path(f"/containers/{parameters.container_id}/logs"),
                params={
                    "stdout": "true",
                    "stderr": "true",
                    "timestamps": "true",
                    "tail": str(query.page.limit),
                    "since": str(max(0, now - parameters.since_seconds_ago)),
                    "until": str(now),
                },
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            items = self._log_lines(payload, limit=query.page.limit)
            return ReadOnlyPage(
                items=items,
                payload_bytes=len(payload),
                truncated=len(items) == query.page.limit,
                cache_hint=CacheHint(max_age_seconds=0, scope="request"),
            )

        if query.operation == "docker.events.list":
            parameters = EventListParameters.model_validate(query.parameters)
            if parameters.since_seconds_ago > self.settings.docker_max_event_window_seconds:
                raise ValueError(
                    "requested event window exceeds DOCKER_MAX_EVENT_WINDOW_SECONDS"
                )
            if any(object_type not in _EVENT_TYPES for object_type in parameters.object_types):
                raise ValueError("unsupported Docker event object type")
            now = int(time.time())
            payload = await self._get_bytes(
                self._api_path("/events"),
                params={
                    "since": str(max(0, now - parameters.since_seconds_ago)),
                    "until": str(now),
                    "filters": json.dumps(
                        {"type": parameters.object_types},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                },
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            items = self._event_items(payload, limit=query.page.limit)
            return ReadOnlyPage(
                items=items,
                payload_bytes=len(payload),
                truncated=len(items) == query.page.limit,
                cache_hint=CacheHint(max_age_seconds=0, scope="request"),
            )

        raise PermissionError("Docker operation is not implemented by the fixed GET adapter")
