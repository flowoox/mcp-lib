from __future__ import annotations

from typing import Literal

from mcp_common.operations import StrictModel
from pydantic import Field


class DockerSwarmSummary(StrictModel):
    local_node_state: str = Field(alias="localNodeState", max_length=50)
    control_available: bool = Field(alias="controlAvailable")


class DockerSystemSummary(StrictModel):
    server_version: str = Field(alias="serverVersion", max_length=100)
    operating_system: str = Field(alias="operatingSystem", max_length=200)
    os_type: str = Field(alias="osType", max_length=50)
    architecture: str = Field(max_length=50)
    driver: str = Field(max_length=100)
    containers: int | None = Field(default=None, ge=0)
    containers_running: int | None = Field(default=None, alias="containersRunning", ge=0)
    containers_paused: int | None = Field(default=None, alias="containersPaused", ge=0)
    containers_stopped: int | None = Field(default=None, alias="containersStopped", ge=0)
    images: int | None = Field(default=None, ge=0)
    cpu_count: int | None = Field(default=None, alias="cpuCount", ge=0)
    memory_bytes: int | None = Field(default=None, alias="memoryBytes", ge=0)
    swarm: DockerSwarmSummary


class DockerMountSummary(StrictModel):
    type: str = Field(max_length=40)
    name: str = Field(max_length=200)
    destination: str = Field(max_length=500)


class DockerPortSummary(StrictModel):
    private_port: int | None = Field(default=None, alias="privatePort", ge=0, le=65_535)
    public_port: int | None = Field(default=None, alias="publicPort", ge=0, le=65_535)
    type: str = Field(max_length=10)
    published: bool


class DockerNestedTruncation(StrictModel):
    names: bool
    networks: bool
    mounts: bool
    ports: bool


class DockerContainerSummary(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    names: list[str] = Field(max_length=8)
    image: str = Field(max_length=500)
    image_id: str = Field(alias="imageId", max_length=200)
    created: int | None = Field(default=None, ge=0)
    state: str = Field(max_length=50)
    status: str = Field(max_length=300)
    networks: list[str] = Field(max_length=16)
    mounts: list[DockerMountSummary] = Field(max_length=16)
    ports: list[DockerPortSummary] = Field(max_length=32)
    nested_truncated: DockerNestedTruncation = Field(alias="nestedTruncated")


class DockerLogLine(StrictModel):
    timestamp: str | None = Field(default=None, max_length=64)
    stream: Literal["stdout", "stderr", "unknown"] = "unknown"
    message: str = Field(max_length=8_192)


class DockerEventSummary(StrictModel):
    type: str = Field(max_length=40)
    action: str = Field(max_length=80)
    actor_id: str = Field(alias="actorId", max_length=128)
    scope: str = Field(max_length=40)
    time: int | None = Field(default=None, ge=0)
    time_nano: int | None = Field(default=None, alias="timeNano", ge=0)
    attributes: dict[str, str] = Field(default_factory=dict, max_length=8)


class DockerReferenceTruncation(StrictModel):
    repo_tags: bool = Field(alias="repoTags")
    repo_digests: bool = Field(alias="repoDigests")


class DockerImageSummary(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    repo_tags: list[str] = Field(alias="repoTags", max_length=16)
    repo_digests: list[str] = Field(alias="repoDigests", max_length=16)
    created: int | None = Field(default=None, ge=0)
    size_bytes: int | None = Field(default=None, alias="sizeBytes", ge=0)
    dangling: bool
    nested_truncated: DockerReferenceTruncation = Field(alias="nestedTruncated")


class DockerVolumeSummary(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    driver: str = Field(max_length=100)
    scope: str = Field(max_length=40)
    created_at: str | None = Field(default=None, alias="createdAt", max_length=80)
    usage_bytes: int | None = Field(default=None, alias="usageBytes", ge=0)
    ref_count: int | None = Field(default=None, alias="refCount", ge=0)


class DockerNetworkSummary(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    driver: str = Field(max_length=100)
    scope: str = Field(max_length=40)
    internal: bool
    attachable: bool
    ingress: bool
    ipv6_enabled: bool = Field(alias="ipv6Enabled")
    ipam_driver: str = Field(alias="ipamDriver", max_length=100)
    ipam_config_count: int = Field(alias="ipamConfigCount", ge=0)
    attached_container_count: int = Field(alias="attachedContainerCount", ge=0)


class DockerContainerStatsSummary(StrictModel):
    container_id: str = Field(alias="containerId", min_length=1, max_length=128)
    read_at: str | None = Field(default=None, alias="readAt", max_length=80)
    pids: int | None = Field(default=None, ge=0)
    cpu_percent: float | None = Field(default=None, alias="cpuPercent", ge=0)
    cpu_total_usage: int | None = Field(default=None, alias="cpuTotalUsage", ge=0)
    system_cpu_usage: int | None = Field(default=None, alias="systemCpuUsage", ge=0)
    online_cpus: int | None = Field(default=None, alias="onlineCpus", ge=0)
    memory_usage_bytes: int | None = Field(default=None, alias="memoryUsageBytes", ge=0)
    memory_working_set_bytes: int | None = Field(
        default=None, alias="memoryWorkingSetBytes", ge=0
    )
    memory_limit_bytes: int | None = Field(default=None, alias="memoryLimitBytes", ge=0)
    memory_percent: float | None = Field(default=None, alias="memoryPercent", ge=0)
    network_rx_bytes: int = Field(alias="networkRxBytes", ge=0)
    network_tx_bytes: int = Field(alias="networkTxBytes", ge=0)
    block_read_bytes: int = Field(alias="blockReadBytes", ge=0)
    block_write_bytes: int = Field(alias="blockWriteBytes", ge=0)
