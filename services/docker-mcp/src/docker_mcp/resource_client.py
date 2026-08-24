from __future__ import annotations

import re
from typing import Any

from mcp_common.operations import StrictModel
from mcp_common.read_only_connector import CacheHint, ReadOnlyPage, ReadOnlyQuery
from pydantic import Field, field_validator

from .client import DockerApiTransport, DockerClientError
from .models import (
    DockerContainerStatsSummary,
    DockerImageSummary,
    DockerNetworkSummary,
    DockerVolumeSummary,
)

_CONTAINER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ContainerStatsParameters(StrictModel):
    container_id: str = Field(min_length=1, max_length=128)

    @field_validator("container_id")
    @classmethod
    def validate_container_id(cls, value: str) -> str:
        normalized = value.strip()
        if not _CONTAINER_ID_RE.fullmatch(normalized):
            raise ValueError("container_id must be a Docker ID or simple container name")
        return normalized


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class DockerResourceApiTransport(DockerApiTransport):
    """Read-only Docker adapter extension for bounded inventory and one-shot statistics."""

    @staticmethod
    def _image_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker image list contained a non-object item")
        raw_tags = value.get("RepoTags")
        raw_digests = value.get("RepoDigests")
        tags = DockerApiTransport._bounded_strings(raw_tags, limit=16, max_length=500)
        digests = DockerApiTransport._bounded_strings(raw_digests, limit=16, max_length=500)
        summary = DockerImageSummary.model_validate(
            {
                "id": str(value.get("Id") or value.get("ID") or "")[:200],
                "repoTags": tags,
                "repoDigests": digests,
                "created": _nonnegative_int(value.get("Created")),
                "sizeBytes": _nonnegative_int(value.get("Size")),
                "dangling": len(tags) == 0,
                "nestedTruncated": {
                    "repoTags": isinstance(raw_tags, list) and len(raw_tags) > 16,
                    "repoDigests": isinstance(raw_digests, list) and len(raw_digests) > 16,
                },
            }
        )
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _volume_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker volume list contained a non-object item")
        usage = _mapping(value.get("UsageData"))
        summary = DockerVolumeSummary.model_validate(
            {
                "name": str(value.get("Name") or "")[:255],
                "driver": str(value.get("Driver") or "")[:100],
                "scope": str(value.get("Scope") or "")[:40],
                "createdAt": (
                    str(value.get("CreatedAt"))[:80] if value.get("CreatedAt") is not None else None
                ),
                "usageBytes": _nonnegative_int(usage.get("Size")),
                "refCount": _nonnegative_int(usage.get("RefCount")),
            }
        )
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _network_summary(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker network list contained a non-object item")
        ipam = _mapping(value.get("IPAM"))
        config = ipam.get("Config")
        containers = value.get("Containers")
        summary = DockerNetworkSummary.model_validate(
            {
                "id": str(value.get("Id") or value.get("ID") or "")[:128],
                "name": str(value.get("Name") or "")[:255],
                "driver": str(value.get("Driver") or "")[:100],
                "scope": str(value.get("Scope") or "")[:40],
                "internal": bool(value.get("Internal", False)),
                "attachable": bool(value.get("Attachable", False)),
                "ingress": bool(value.get("Ingress", False)),
                "ipv6Enabled": bool(value.get("EnableIPv6", False)),
                "ipamDriver": str(ipam.get("Driver") or "")[:100],
                "ipamConfigCount": len(config) if isinstance(config, list) else 0,
                "attachedContainerCount": len(containers) if isinstance(containers, dict) else 0,
            }
        )
        return summary.model_dump(mode="json", by_alias=True)

    @staticmethod
    def _container_stats_summary(container_id: str, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise DockerClientError("Docker container stats response must be an object")

        cpu_stats = _mapping(value.get("cpu_stats"))
        cpu_usage = _mapping(cpu_stats.get("cpu_usage"))
        precpu_stats = _mapping(value.get("precpu_stats"))
        precpu_usage = _mapping(precpu_stats.get("cpu_usage"))
        cpu_total = _nonnegative_int(cpu_usage.get("total_usage"))
        precpu_total = _nonnegative_int(precpu_usage.get("total_usage"))
        system_cpu = _nonnegative_int(cpu_stats.get("system_cpu_usage"))
        pre_system_cpu = _nonnegative_int(precpu_stats.get("system_cpu_usage"))
        online_cpus = _nonnegative_int(cpu_stats.get("online_cpus"))
        if online_cpus is None:
            per_cpu = cpu_usage.get("percpu_usage")
            online_cpus = len(per_cpu) if isinstance(per_cpu, list) else None

        cpu_percent: float | None = None
        if (
            cpu_total is not None
            and precpu_total is not None
            and system_cpu is not None
            and pre_system_cpu is not None
            and online_cpus is not None
        ):
            cpu_delta = cpu_total - precpu_total
            system_delta = system_cpu - pre_system_cpu
            if cpu_delta >= 0 and system_delta > 0:
                cpu_percent = cpu_delta / system_delta * online_cpus * 100.0

        memory_stats = _mapping(value.get("memory_stats"))
        memory_usage = _nonnegative_int(memory_stats.get("usage"))
        memory_limit = _nonnegative_int(memory_stats.get("limit"))
        memory_detail = _mapping(memory_stats.get("stats"))
        inactive_file = _nonnegative_int(memory_detail.get("inactive_file"))
        cache = inactive_file
        if cache is None:
            cache = _nonnegative_int(memory_detail.get("cache"))
        working_set = memory_usage
        if memory_usage is not None and cache is not None:
            working_set = max(0, memory_usage - cache)
        memory_percent = (
            working_set / memory_limit * 100.0
            if working_set is not None and memory_limit is not None and memory_limit > 0
            else None
        )

        network_rx = 0
        network_tx = 0
        networks = value.get("networks")
        if isinstance(networks, dict):
            for counters in networks.values():
                if not isinstance(counters, dict):
                    continue
                network_rx += _nonnegative_int(counters.get("rx_bytes")) or 0
                network_tx += _nonnegative_int(counters.get("tx_bytes")) or 0

        block_read = 0
        block_write = 0
        blkio_stats = _mapping(value.get("blkio_stats"))
        io_entries = blkio_stats.get("io_service_bytes_recursive")
        if isinstance(io_entries, list):
            for entry in io_entries:
                if not isinstance(entry, dict):
                    continue
                amount = _nonnegative_int(entry.get("value"))
                if amount is None:
                    continue
                operation = str(entry.get("op") or "").casefold()
                if operation == "read":
                    block_read += amount
                elif operation == "write":
                    block_write += amount

        pids = _nonnegative_int(_mapping(value.get("pids_stats")).get("current"))
        summary = DockerContainerStatsSummary.model_validate(
            {
                "containerId": container_id,
                "readAt": str(value.get("read"))[:80] if value.get("read") is not None else None,
                "pids": pids,
                "cpuPercent": cpu_percent,
                "cpuTotalUsage": cpu_total,
                "systemCpuUsage": system_cpu,
                "onlineCpus": online_cpus,
                "memoryUsageBytes": memory_usage,
                "memoryWorkingSetBytes": working_set,
                "memoryLimitBytes": memory_limit,
                "memoryPercent": memory_percent,
                "networkRxBytes": network_rx,
                "networkTxBytes": network_tx,
                "blockReadBytes": block_read,
                "blockWriteBytes": block_write,
            }
        )
        return summary.model_dump(mode="json", by_alias=True)

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage:
        if query.operation not in {
            "docker.images.list",
            "docker.volumes.list",
            "docker.networks.list",
            "docker.containers.stats",
        }:
            return await super().query(
                query,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )

        if query.page.cursor is not None:
            raise ValueError("Docker resource inventory has no stable cursor")

        if query.operation == "docker.images.list":
            if query.parameters:
                raise ValueError("docker.images.list does not accept parameters")
            payload, size = await self._get_json(
                self._api_path("/images/json"),
                params={"all": "false"},
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            if not isinstance(payload, list):
                raise DockerClientError("Docker image list response must be an array")
            raw_count = len(payload)
            items = [self._image_summary(item) for item in payload[: query.page.limit]]
            return ReadOnlyPage(
                items=items,
                payload_bytes=size,
                truncated=raw_count > query.page.limit,
                cache_hint=CacheHint(max_age_seconds=10),
            )

        if query.operation == "docker.volumes.list":
            if query.parameters:
                raise ValueError("docker.volumes.list does not accept parameters")
            payload, size = await self._get_json(
                self._api_path("/volumes"),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            if not isinstance(payload, dict):
                raise DockerClientError("Docker volume list response must be an object")
            raw_volumes = payload.get("Volumes")
            volumes = raw_volumes if isinstance(raw_volumes, list) else []
            items = [self._volume_summary(item) for item in volumes[: query.page.limit]]
            return ReadOnlyPage(
                items=items,
                payload_bytes=size,
                truncated=len(volumes) > query.page.limit,
                cache_hint=CacheHint(max_age_seconds=10),
            )

        if query.operation == "docker.networks.list":
            if query.parameters:
                raise ValueError("docker.networks.list does not accept parameters")
            payload, size = await self._get_json(
                self._api_path("/networks"),
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            if not isinstance(payload, list):
                raise DockerClientError("Docker network list response must be an array")
            raw_count = len(payload)
            items = [self._network_summary(item) for item in payload[: query.page.limit]]
            return ReadOnlyPage(
                items=items,
                payload_bytes=size,
                truncated=raw_count > query.page.limit,
                cache_hint=CacheHint(max_age_seconds=10),
            )

        parameters = ContainerStatsParameters.model_validate(query.parameters)
        payload, size = await self._get_json(
            self._api_path(f"/containers/{parameters.container_id}/stats"),
            params={"stream": "false", "one-shot": "true"},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        return ReadOnlyPage(
            items=[self._container_stats_summary(parameters.container_id, payload)],
            payload_bytes=size,
            cache_hint=CacheHint(max_age_seconds=2, scope="request"),
        )
