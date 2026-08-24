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
