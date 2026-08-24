import asyncio
import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery

from docker_mcp.config import Settings
from docker_mcp.resource_client import DockerResourceApiTransport


def settings() -> Settings:
    return Settings(
        docker_host="https://docker.example.invalid:2376",
        docker_backend_read_only=True,
        docker_auth_token="not-returned",
    )


def test_image_inventory_is_bounded_and_omits_labels_and_raw_config() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json=[
                {
                    "Id": "sha256:" + "a" * 64,
                    "RepoTags": ["example/web:1", "example/web:latest"],
                    "RepoDigests": ["example/web@sha256:" + "b" * 64],
                    "Created": 123,
                    "Size": 1000,
                    "Labels": {"credential": "secret-value"},
                    "ParentId": "sensitive-parent",
                },
                {
                    "Id": "sha256:" + "c" * 64,
                    "RepoTags": [],
                    "RepoDigests": [],
                    "Created": 122,
                    "Size": 500,
                },
            ],
        )

    transport = DockerResourceApiTransport(settings(), transport=httpx.MockTransport(handler))
    page = asyncio.run(
        transport.query(
            ReadOnlyQuery(operation="docker.images.list", page=PageRequest(limit=1)),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
    )

    assert seen[0].method == "GET"
    assert seen[0].url.path == "/v1.47/images/json"
    assert seen[0].url.params["all"] == "false"
    assert page.truncated is True
    assert len(page.items) == 1
    assert page.items[0]["repoTags"] == ["example/web:1", "example/web:latest"]
    rendered = json.dumps(page.items)
    assert "Labels" not in rendered
    assert "secret-value" not in rendered
    assert "sensitive-parent" not in rendered


def test_volume_and_network_inventory_minimize_host_and_endpoint_topology() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v1.47/volumes":
            return httpx.Response(
                200,
                json={
                    "Volumes": [
                        {
                            "Name": "db-data",
                            "Driver": "local",
                            "Scope": "local",
                            "CreatedAt": "2026-08-24T08:00:00Z",
                            "Mountpoint": "/var/lib/docker/volumes/db-data/_data",
                            "Labels": {"secret": "volume-label"},
                            "Options": {"device": "//fileserver/private", "password": "secret"},
                            "UsageData": {"Size": 4096, "RefCount": 2},
                        }
                    ],
                    "Warnings": ["internal detail"],
                },
            )
        if request.url.path == "/v1.47/networks":
            return httpx.Response(
                200,
                json=[
                    {
                        "Id": "n" * 64,
                        "Name": "frontend",
                        "Driver": "bridge",
                        "Scope": "local",
                        "Internal": False,
                        "Attachable": False,
                        "Ingress": False,
                        "EnableIPv6": True,
                        "IPAM": {
                            "Driver": "default",
                            "Config": [
                                {"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"},
                                {"Subnet": "fd00::/64", "Gateway": "fd00::1"},
                            ],
                        },
                        "Containers": {
                            "container-secret-id": {
                                "Name": "web",
                                "IPv4Address": "172.30.0.2/16",
                                "MacAddress": "02:42:ac:1e:00:02",
                            }
                        },
                        "Labels": {"credential": "network-label"},
                        "Options": {"com.docker.network.bridge.name": "br-private"},
                    }
                ],
            )
        raise AssertionError(request.url.path)

    transport = DockerResourceApiTransport(settings(), transport=httpx.MockTransport(handler))

    async def exercise() -> tuple[object, object]:
        volumes = await transport.query(
            ReadOnlyQuery(operation="docker.volumes.list", page=PageRequest(limit=10)),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
        networks = await transport.query(
            ReadOnlyQuery(operation="docker.networks.list", page=PageRequest(limit=10)),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
        return volumes, networks

    volumes, networks = asyncio.run(exercise())
    volume = volumes.items[0]
    assert volume == {
        "name": "db-data",
        "driver": "local",
        "scope": "local",
        "createdAt": "2026-08-24T08:00:00Z",
        "usageBytes": 4096,
        "refCount": 2,
    }
    network = networks.items[0]
    assert network["name"] == "frontend"
    assert network["ipamConfigCount"] == 2
    assert network["attachedContainerCount"] == 1
    rendered = json.dumps({"volumes": volumes.items, "networks": networks.items})
    for secret in (
        "/var/lib/docker/volumes",
        "volume-label",
        "//fileserver/private",
        "172.30.0.0/16",
        "172.30.0.2/16",
        "02:42:ac:1e:00:02",
        "container-secret-id",
        "network-label",
        "br-private",
    ):
        assert secret not in rendered


def test_container_stats_are_one_shot_normalized_and_path_safe() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "read": "2026-08-24T08:00:00.000000000Z",
                "pids_stats": {"current": 7},
                "cpu_stats": {
                    "cpu_usage": {"total_usage": 300},
                    "system_cpu_usage": 1000,
                    "online_cpus": 2,
                },
                "precpu_stats": {
                    "cpu_usage": {"total_usage": 100},
                    "system_cpu_usage": 600,
                },
                "memory_stats": {
                    "usage": 1000,
                    "limit": 2000,
                    "stats": {"inactive_file": 200, "secret_metric": 999},
                },
                "networks": {
                    "eth0": {"rx_bytes": 10, "tx_bytes": 20, "endpoint_id": "secret"},
                    "eth1": {"rx_bytes": 30, "tx_bytes": 40},
                },
                "blkio_stats": {
                    "io_service_bytes_recursive": [
                        {"op": "Read", "value": 100},
                        {"op": "Write", "value": 200},
                    ]
                },
            },
        )

    transport = DockerResourceApiTransport(settings(), transport=httpx.MockTransport(handler))
    page = asyncio.run(
        transport.query(
            ReadOnlyQuery(
                operation="docker.containers.stats",
                parameters={"container_id": "web-01"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
    )

    request = seen[0]
    assert request.method == "GET"
    assert request.url.path == "/v1.47/containers/web-01/stats"
    assert request.url.params == httpx.QueryParams({"stream": "false", "one-shot": "true"})
    stats = page.items[0]
    assert stats["containerId"] == "web-01"
    assert stats["pids"] == 7
    assert stats["cpuPercent"] == pytest.approx(100.0)
    assert stats["memoryWorkingSetBytes"] == 800
    assert stats["memoryPercent"] == pytest.approx(40.0)
    assert stats["networkRxBytes"] == 40
    assert stats["networkTxBytes"] == 60
    assert stats["blockReadBytes"] == 100
    assert stats["blockWriteBytes"] == 200
    rendered = json.dumps(stats)
    assert "secret_metric" not in rendered
    assert "endpoint_id" not in rendered

    with pytest.raises(ValueError, match="container_id"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.containers.stats",
                    parameters={"container_id": "../../var/run/docker.sock"},
                    page=PageRequest(limit=1),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )


def test_resource_queries_reject_cursors_and_arbitrary_parameters() -> None:
    transport = DockerResourceApiTransport(
        settings(),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
    )
    with pytest.raises(ValueError, match="no stable cursor"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.images.list",
                    page=PageRequest(limit=5, cursor="caller-cursor"),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
    with pytest.raises(ValueError, match="does not accept parameters"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.networks.list",
                    parameters={"filter": "label=secret"},
                    page=PageRequest(limit=5),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
