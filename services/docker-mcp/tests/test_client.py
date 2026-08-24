import asyncio
import json

import httpx
import pytest
from mcp_common.read_only_connector import PageRequest, ReadOnlyQuery
from pydantic import SecretStr

from docker_mcp.client import DockerApiTransport, DockerClientError
from docker_mcp.config import Settings


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "docker_host": "https://docker.example.invalid:2376",
        "docker_backend_read_only": True,
        "docker_auth_token": SecretStr("not-returned"),
    }
    values.update(overrides)
    return Settings(**values)


def test_container_inventory_uses_only_fixed_get_and_redacts_raw_fields() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = [
            {
                "Id": "a" * 64,
                "Names": ["/web"],
                "Image": "example/web:1",
                "ImageID": "sha256:" + "b" * 64,
                "Command": "server --password=secret",
                "Labels": {"secret": "value"},
                "Created": 123,
                "State": "running",
                "Status": "Up 5 minutes",
                "NetworkSettings": {"Networks": {"frontend": {}, "backend": {}}},
                "Mounts": [
                    {
                        "Type": "volume",
                        "Name": "web-data",
                        "Source": "/sensitive/host/path",
                        "Destination": "/data",
                    }
                ],
                "Ports": [
                    {"PrivatePort": 8080, "PublicPort": 8443, "IP": "10.1.2.3", "Type": "tcp"}
                ],
            }
        ]
        return httpx.Response(200, json=payload)

    transport = DockerApiTransport(
        settings(),
        transport=httpx.MockTransport(handler),
    )
    page = asyncio.run(
        transport.query(
            ReadOnlyQuery(
                operation="docker.containers.list",
                parameters={"include_stopped": True},
                page=PageRequest(limit=5),
            ),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
    )

    assert len(seen) == 1
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/v1.47/containers/json"
    assert seen[0].url.params["all"] == "true"
    assert seen[0].url.params["limit"] == "5"
    assert seen[0].headers["authorization"] == "Bearer not-returned"
    container = page.items[0]
    assert container["networks"] == ["backend", "frontend"]
    assert container["mounts"] == [
        {"type": "volume", "name": "web-data", "destination": "/data"}
    ]
    rendered = json.dumps(container)
    assert "Command" not in rendered
    assert "Labels" not in rendered
    assert "secret" not in rendered
    assert "/sensitive/host/path" not in rendered
    assert "10.1.2.3" not in rendered


def test_ping_and_info_are_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/_ping":
            return httpx.Response(200, text="OK")
        if request.url.path == "/v1.47/info":
            return httpx.Response(
                200,
                json={
                    "ServerVersion": "27.0",
                    "Containers": 3,
                    "ContainersRunning": 2,
                    "Images": 10,
                    "NCPU": 8,
                    "MemTotal": 1024,
                    "Driver": "overlay2",
                    "Swarm": {"LocalNodeState": "inactive"},
                    "RegistryConfig": {"IndexConfigs": {"private": {"Mirrors": ["secret"]}}},
                },
            )
        raise AssertionError(request.url.path)

    transport = DockerApiTransport(settings(), transport=httpx.MockTransport(handler))

    async def exercise() -> tuple[object, object]:
        ping = await transport.query(
            ReadOnlyQuery(operation="docker.system.ping", page=PageRequest(limit=1)),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
        info = await transport.query(
            ReadOnlyQuery(operation="docker.system.info", page=PageRequest(limit=1)),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
        return ping.items[0], info.items[0]

    ping, info = asyncio.run(exercise())
    assert ping == {"ok": True}
    assert info["serverVersion"] == "27.0"
    assert "RegistryConfig" not in info


def test_container_logs_are_finite_bounded_demuxed_and_redacted() -> None:
    seen: list[httpx.Request] = []

    def frame(stream: int, text: str) -> bytes:
        payload = text.encode()
        return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload

    payload = frame(
        1,
        "2026-08-24T08:00:00.000000000Z started password=hunter2\n",
    ) + frame(
        2,
        "2026-08-24T08:00:01.000000000Z Authorization: Bearer abcdefghijklmnop\n",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=payload)

    transport = DockerApiTransport(settings(), transport=httpx.MockTransport(handler))
    page = asyncio.run(
        transport.query(
            ReadOnlyQuery(
                operation="docker.containers.logs",
                parameters={"container_id": "web-01", "since_seconds_ago": 120},
                page=PageRequest(limit=2),
            ),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
    )

    request = seen[0]
    assert request.method == "GET"
    assert request.url.path == "/v1.47/containers/web-01/logs"
    assert request.url.params["stdout"] == "true"
    assert request.url.params["stderr"] == "true"
    assert request.url.params["timestamps"] == "true"
    assert request.url.params["tail"] == "2"
    assert "follow" not in request.url.params
    assert 1 <= int(request.url.params["until"]) - int(request.url.params["since"]) <= 120
    assert page.items[0]["stream"] == "stdout"
    assert page.items[1]["stream"] == "stderr"
    rendered = json.dumps(page.items)
    assert "hunter2" not in rendered
    assert "abcdefghijklmnop" not in rendered
    assert "[REDACTED]" in rendered


def test_recent_events_use_finite_window_fixed_filter_and_minimized_attributes() -> None:
    seen: list[httpx.Request] = []
    payload = b"\n".join(
        [
            json.dumps(
                {
                    "Type": "container",
                    "Action": "die",
                    "Actor": {
                        "ID": "a" * 64,
                        "Attributes": {
                            "name": "web",
                            "image": "example/web:1",
                            "exitCode": "1",
                            "secret.label": "do-not-return",
                        },
                    },
                    "scope": "local",
                    "time": 123,
                    "timeNano": 123000000000,
                }
            ).encode(),
            json.dumps(
                {
                    "Type": "container",
                    "Action": "start",
                    "Actor": {"ID": "b" * 64, "Attributes": {"name": "worker"}},
                    "scope": "local",
                    "time": 124,
                    "timeNano": 124000000000,
                }
            ).encode(),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=payload)

    transport = DockerApiTransport(settings(), transport=httpx.MockTransport(handler))
    page = asyncio.run(
        transport.query(
            ReadOnlyQuery(
                operation="docker.events.list",
                parameters={"since_seconds_ago": 60, "object_types": ["container"]},
                page=PageRequest(limit=2),
            ),
            timeout_seconds=1,
            max_response_bytes=16_384,
        )
    )

    request = seen[0]
    assert request.method == "GET"
    assert request.url.path == "/v1.47/events"
    assert json.loads(request.url.params["filters"]) == {"type": ["container"]}
    assert 1 <= int(request.url.params["until"]) - int(request.url.params["since"]) <= 60
    assert page.items[0]["attributes"] == {
        "image": "example/web:1",
        "name": "web",
        "exitCode": "1",
    }
    assert "do-not-return" not in json.dumps(page.items)


def test_log_target_and_diagnostic_windows_fail_closed() -> None:
    transport = DockerApiTransport(
        settings(docker_max_log_window_seconds=60, docker_max_event_window_seconds=30),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"")),
    )
    with pytest.raises(ValueError, match="container_id"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.containers.logs",
                    parameters={"container_id": "../../etc/passwd", "since_seconds_ago": 10},
                    page=PageRequest(limit=1),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
    with pytest.raises(ValueError, match="LOG_WINDOW"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.containers.logs",
                    parameters={"container_id": "web", "since_seconds_ago": 61},
                    page=PageRequest(limit=1),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
    with pytest.raises(ValueError, match="EVENT_WINDOW"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.events.list",
                    parameters={"since_seconds_ago": 31, "object_types": ["container"]},
                    page=PageRequest(limit=1),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )


def test_cursors_redirects_and_oversized_responses_fail_closed() -> None:
    transport = DockerApiTransport(
        settings(),
        transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "/other"})),
    )
    with pytest.raises(ValueError, match="no stable cursor"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(
                    operation="docker.containers.list",
                    page=PageRequest(limit=5, cursor="agent-value"),
                ),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
    with pytest.raises(DockerClientError, match="redirects"):
        asyncio.run(
            transport.query(
                ReadOnlyQuery(operation="docker.system.ping", page=PageRequest(limit=1)),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )

    oversized = DockerApiTransport(
        settings(),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"x" * 16_385)
        ),
    )
    with pytest.raises(DockerClientError, match="byte limit"):
        asyncio.run(
            oversized.query(
                ReadOnlyQuery(operation="docker.system.ping", page=PageRequest(limit=1)),
                timeout_seconds=1,
                max_response_bytes=16_384,
            )
        )
