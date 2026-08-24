from __future__ import annotations

import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

import httpx

from docker_mcp.readonly_proxy import (
    BoundedThreadingHTTPServer,
    DockerReadOnlyPolicy,
    ProxyConfig,
    _handler,
)


class FakeDockerHandler(BaseHTTPRequestHandler):
    seen: list[dict[str, Any]] = []

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def do_GET(self) -> None:
        self.__class__.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
            }
        )
        payload = json.dumps({"ServerVersion": "27.0"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Docker-Experimental", "false")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class UnixDockerServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


def _config(socket_path: Path) -> ProxyConfig:
    return ProxyConfig(
        bind_host="127.0.0.1",
        bind_port=0,
        docker_socket_path=str(socket_path),
        tls_cert_file="/unused/proxy.crt",
        tls_key_file="/unused/proxy.key",
        bearer_token_file="/unused/proxy.token",
        api_version="v1.47",
        max_page_size=100,
        max_log_window_seconds=3_600,
        max_event_window_seconds=300,
        upstream_timeout_seconds=2.0,
        max_response_bytes=16_384,
        max_concurrency=2,
    )


def test_proxy_handler_authenticates_authorizes_and_strips_backend_credential(tmp_path: Path) -> None:
    socket_path = tmp_path / "docker.sock"
    FakeDockerHandler.seen = []
    docker_server = UnixDockerServer(str(socket_path), FakeDockerHandler)
    docker_thread = threading.Thread(target=docker_server.serve_forever, daemon=True)
    docker_thread.start()

    config = _config(socket_path)
    proxy_handler = _handler(config, DockerReadOnlyPolicy(
        api_version="v1.47",
        max_page_size=100,
        max_log_window_seconds=3_600,
        max_event_window_seconds=300,
    ), "a" * 48)
    proxy_server = BoundedThreadingHTTPServer(
        ("127.0.0.1", 0), proxy_handler, max_concurrency=2
    )
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()

    try:
        host, port = proxy_server.server_address
        base_url = f"http://{host}:{port}"
        with httpx.Client(base_url=base_url, timeout=2.0) as client:
            unauthorized = client.get("/v1.47/info")
            assert unauthorized.status_code == 401
            assert FakeDockerHandler.seen == []

            forbidden = client.get(
                "/v1.47/version",
                headers={"Authorization": f"Bearer {'a' * 48}"},
            )
            assert forbidden.status_code == 403
            assert FakeDockerHandler.seen == []

            method_denied = client.post(
                "/v1.47/info",
                headers={"Authorization": f"Bearer {'a' * 48}"},
            )
            assert method_denied.status_code == 405
            assert FakeDockerHandler.seen == []

            allowed = client.get(
                "/v1.47/info",
                headers={"Authorization": f"Bearer {'a' * 48}"},
            )
            assert allowed.status_code == 200
            assert allowed.json() == {"ServerVersion": "27.0"}
            assert allowed.headers["docker-experimental"] == "false"
            assert FakeDockerHandler.seen == [
                {"method": "GET", "path": "/v1.47/info", "authorization": None}
            ]
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        docker_server.shutdown()
        docker_server.server_close()
        proxy_thread.join(timeout=2)
        docker_thread.join(timeout=2)
