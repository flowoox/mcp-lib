from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx
from mcp_common.operations import StrictModel
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery

from .config import Settings, normalize_docker_host
from .models import DockerContainerSummary, DockerSystemSummary


class DockerClientError(RuntimeError):
    pass


class ContainerListParameters(StrictModel):
    include_stopped: bool = False


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

        raise PermissionError("Docker operation is not implemented by the fixed GET adapter")
