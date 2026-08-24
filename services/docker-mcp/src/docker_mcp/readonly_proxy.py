from __future__ import annotations

import hmac
import json
import os
import re
import ssl
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx

_API_VERSION_RE = re.compile(r"^v1\.(\d{2})$")
_CONTAINER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_EVENT_TYPES = frozenset({"container", "image", "volume", "network", "daemon"})
_RESPONSE_HEADERS = frozenset({"content-type", "api-version", "docker-experimental", "ostype"})
_MAX_REQUEST_TARGET_CHARS = 2_048
_MAX_QUERY_FIELDS = 8
_MAX_TIMESTAMP = 9_223_372_036_854_775_807


@dataclass(frozen=True)
class ProxyConfig:
    bind_host: str
    bind_port: int
    docker_socket_path: str
    tls_cert_file: str
    tls_key_file: str
    bearer_token_file: str
    api_version: str
    max_page_size: int
    max_log_window_seconds: int
    max_event_window_seconds: int
    upstream_timeout_seconds: float
    max_response_bytes: int
    max_concurrency: int

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ProxyConfig:
        values = os.environ if env is None else env

        def required_path(name: str) -> str:
            raw = values.get(name, "").strip()
            if not raw:
                raise ValueError(f"{name} must be configured")
            path = PurePosixPath(raw)
            if not path.is_absolute() or "%" in raw or "\\" in raw:
                raise ValueError(f"{name} must be an absolute literal POSIX path")
            return raw

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            raw = values.get(name, str(default)).strip()
            try:
                parsed = int(raw, 10)
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not minimum <= parsed <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return parsed

        def decimal(name: str, default: float, minimum: float, maximum: float) -> float:
            raw = values.get(name, str(default)).strip()
            try:
                parsed = float(raw)
            except ValueError as exc:
                raise ValueError(f"{name} must be a number") from exc
            if not minimum <= parsed <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return parsed

        bind_host = values.get("DOCKER_READONLY_PROXY_BIND_HOST", "127.0.0.1").strip()
        if not bind_host or len(bind_host) > 255 or any(ord(char) < 32 for char in bind_host):
            raise ValueError("DOCKER_READONLY_PROXY_BIND_HOST is invalid")

        api_version = values.get("DOCKER_READONLY_PROXY_API_VERSION", "v1.47").strip()
        match = _API_VERSION_RE.fullmatch(api_version)
        if match is None or not 24 <= int(match.group(1)) <= 99:
            raise ValueError("DOCKER_READONLY_PROXY_API_VERSION must be between v1.24 and v1.99")

        return cls(
            bind_host=bind_host,
            bind_port=integer("DOCKER_READONLY_PROXY_BIND_PORT", 23760, 1, 65_535),
            docker_socket_path=required_path("DOCKER_READONLY_PROXY_DOCKER_SOCKET"),
            tls_cert_file=required_path("DOCKER_READONLY_PROXY_TLS_CERT_FILE"),
            tls_key_file=required_path("DOCKER_READONLY_PROXY_TLS_KEY_FILE"),
            bearer_token_file=required_path("DOCKER_READONLY_PROXY_BEARER_TOKEN_FILE"),
            api_version=api_version,
            max_page_size=integer("DOCKER_READONLY_PROXY_MAX_PAGE_SIZE", 100, 1, 500),
            max_log_window_seconds=integer(
                "DOCKER_READONLY_PROXY_MAX_LOG_WINDOW_SECONDS", 3_600, 1, 86_400
            ),
            max_event_window_seconds=integer(
                "DOCKER_READONLY_PROXY_MAX_EVENT_WINDOW_SECONDS", 300, 1, 3_600
            ),
            upstream_timeout_seconds=decimal(
                "DOCKER_READONLY_PROXY_UPSTREAM_TIMEOUT_SECONDS", 8.0, 0.25, 60.0
            ),
            max_response_bytes=integer(
                "DOCKER_READONLY_PROXY_MAX_RESPONSE_BYTES", 16_777_216, 16_384, 67_108_864
            ),
            max_concurrency=integer("DOCKER_READONLY_PROXY_MAX_CONCURRENCY", 4, 1, 32),
        )


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class DockerReadOnlyPolicy:
    """Exact Docker Engine GET policy matching the public docker-mcp adapter surface."""

    def __init__(
        self,
        *,
        api_version: str,
        max_page_size: int,
        max_log_window_seconds: int,
        max_event_window_seconds: int,
    ) -> None:
        if _API_VERSION_RE.fullmatch(api_version) is None:
            raise ValueError("api_version is invalid")
        if not 1 <= max_page_size <= 500:
            raise ValueError("max_page_size must be between 1 and 500")
        if not 1 <= max_log_window_seconds <= 86_400:
            raise ValueError("max_log_window_seconds must be between 1 and 86400")
        if not 1 <= max_event_window_seconds <= 3_600:
            raise ValueError("max_event_window_seconds must be between 1 and 3600")
        self.api_version = api_version
        self.max_page_size = max_page_size
        self.max_log_window_seconds = max_log_window_seconds
        self.max_event_window_seconds = max_event_window_seconds
        escaped = re.escape(f"/{api_version}/containers/")
        self._logs_path = re.compile(escaped + r"([A-Za-z0-9][A-Za-z0-9_.-]{0,127})/logs$")
        self._stats_path = re.compile(escaped + r"([A-Za-z0-9][A-Za-z0-9_.-]{0,127})/stats$")

    @staticmethod
    def _query(target: str) -> tuple[str, dict[str, str]] | None:
        if len(target) > _MAX_REQUEST_TARGET_CHARS or any(ord(char) < 32 for char in target):
            return None
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return None
        try:
            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=_MAX_QUERY_FIELDS,
                separator="&",
            )
        except ValueError:
            return None
        if len({key for key, _ in pairs}) != len(pairs):
            return None
        return parsed.path, dict(pairs)

    @staticmethod
    def _timestamp(value: str | None) -> int | None:
        if value is None or not value.isascii() or not value.isdigit() or len(value) > 19:
            return None
        parsed = int(value, 10)
        return parsed if parsed <= _MAX_TIMESTAMP else None

    @staticmethod
    def _exact_keys(params: dict[str, str], expected: set[str]) -> bool:
        return set(params) == expected

    def _containers_allowed(self, params: dict[str, str]) -> bool:
        if not self._exact_keys(params, {"all", "limit"}) or params["all"] not in {
            "true",
            "false",
        }:
            return False
        limit = self._timestamp(params["limit"])
        return limit is not None and 1 <= limit <= self.max_page_size

    def _logs_allowed(self, params: dict[str, str]) -> bool:
        expected = {"stdout", "stderr", "timestamps", "tail", "since", "until"}
        if not self._exact_keys(params, expected):
            return False
        if (
            params["stdout"] != "true"
            or params["stderr"] != "true"
            or params["timestamps"] != "true"
        ):
            return False
        tail = self._timestamp(params["tail"])
        since = self._timestamp(params["since"])
        until = self._timestamp(params["until"])
        return (
            tail is not None
            and 1 <= tail <= self.max_page_size
            and since is not None
            and until is not None
            and since <= until
            and until - since <= self.max_log_window_seconds
        )

    @staticmethod
    def _stats_allowed(params: dict[str, str]) -> bool:
        return params == {"stream": "false", "one-shot": "true"}

    def _events_allowed(self, params: dict[str, str]) -> bool:
        if not self._exact_keys(params, {"since", "until", "filters"}):
            return False
        since = self._timestamp(params["since"])
        until = self._timestamp(params["until"])
        if (
            since is None
            or until is None
            or since > until
            or until - since > self.max_event_window_seconds
        ):
            return False
        try:
            filters: Any = json.loads(params["filters"])
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(filters, dict) or set(filters) != {"type"}:
            return False
        object_types = filters.get("type")
        if not isinstance(object_types, list) or not 1 <= len(object_types) <= 5:
            return False
        if len(set(object_types)) != len(object_types):
            return False
        return all(isinstance(value, str) and value in _EVENT_TYPES for value in object_types)

    def authorize(self, method: str, target: str) -> PolicyDecision:
        if method != "GET":
            return PolicyDecision(False, "method_not_allowed")
        parsed = self._query(target)
        if parsed is None:
            return PolicyDecision(False, "invalid_request_target")
        path, params = parsed
        root = f"/{self.api_version}"

        if path == "/_ping":
            allowed = not params
        elif path == f"{root}/info":
            allowed = not params
        elif path == f"{root}/containers/json":
            allowed = self._containers_allowed(params)
        elif self._logs_path.fullmatch(path):
            allowed = self._logs_allowed(params)
        elif self._stats_path.fullmatch(path):
            allowed = self._stats_allowed(params)
        elif path == f"{root}/images/json":
            allowed = params == {"all": "false"}
        elif path in {f"{root}/volumes", f"{root}/networks"}:
            allowed = not params
        elif path == f"{root}/events":
            allowed = self._events_allowed(params)
        else:
            return PolicyDecision(False, "path_not_allowed")

        return PolicyDecision(allowed, "allowed" if allowed else "query_not_allowed")


def _load_bearer_token(path: str) -> str:
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("failed to read DOCKER_READONLY_PROXY_BEARER_TOKEN_FILE") from exc
    if not 32 <= len(token) <= 4_096:
        raise ValueError("proxy bearer token must contain 32-4096 characters")
    if not token.isascii() or any(character.isspace() or ord(character) < 33 for character in token):
        raise ValueError("proxy bearer token must be printable ASCII without whitespace")
    return token


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *, max_concurrency: int) -> None:
        self._slots = threading.BoundedSemaphore(max_concurrency)
        super().__init__(server_address, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class DockerReadOnlyProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "flowoox-docker-readonly-proxy/1"
    sys_version = ""
    policy: DockerReadOnlyPolicy
    config: ProxyConfig
    bearer_token: str

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _write(self, status: HTTPStatus | int, payload: bytes, *, content_type: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if payload:
            self.wfile.write(payload)
        self.close_connection = True

    def _reject(self, status: HTTPStatus, code: str) -> None:
        self._write(status, _json_bytes({"error": code}), content_type="application/json")

    def _authenticated(self) -> bool:
        value = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not value.startswith(prefix):
            return False
        supplied = value[len(prefix) :]
        return hmac.compare_digest(supplied, self.bearer_token)

    def _forward(self) -> None:
        transport = httpx.HTTPTransport(uds=self.config.docker_socket_path)
        try:
            with httpx.Client(
                base_url="http://docker",
                transport=transport,
                timeout=httpx.Timeout(self.config.upstream_timeout_seconds),
                follow_redirects=False,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "flowoox-docker-readonly-proxy/1",
                },
            ) as client, client.stream("GET", self.path) as response:
                if 300 <= response.status_code < 400:
                    self._reject(HTTPStatus.BAD_GATEWAY, "upstream_redirect_rejected")
                    return
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared = int(content_length)
                    except ValueError:
                        self._reject(HTTPStatus.BAD_GATEWAY, "invalid_upstream_content_length")
                        return
                    if declared < 0 or declared > self.config.max_response_bytes:
                        self._reject(HTTPStatus.BAD_GATEWAY, "upstream_response_too_large")
                        return

                payload = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > self.config.max_response_bytes - len(payload):
                        self._reject(HTTPStatus.BAD_GATEWAY, "upstream_response_too_large")
                        return
                    payload.extend(chunk)

                if response.status_code >= 400:
                    self._write(
                        response.status_code,
                        _json_bytes({"error": "docker_upstream_error", "status": response.status_code}),
                        content_type="application/json",
                    )
                    return

                content_type = response.headers.get("content-type", "application/octet-stream")
                self.send_response(response.status_code)
                for name, value in response.headers.items():
                    if name.casefold() in _RESPONSE_HEADERS and name.casefold() != "content-type":
                        self.send_header(name, value[:1_024])
                self.send_header("Content-Type", content_type[:1_024])
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                if payload:
                    self.wfile.write(payload)
                self.close_connection = True
        except (httpx.HTTPError, OSError):
            self._reject(HTTPStatus.BAD_GATEWAY, "docker_upstream_unavailable")

    def do_GET(self) -> None:
        if not self._authenticated():
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Bearer realm="docker-readonly-proxy"')
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        decision = self.policy.authorize("GET", self.path)
        if not decision.allowed:
            self._reject(HTTPStatus.FORBIDDEN, decision.reason)
            return
        self._forward()

    def _deny_method(self) -> None:
        self._reject(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    do_POST = _deny_method
    do_PUT = _deny_method
    do_PATCH = _deny_method
    do_DELETE = _deny_method
    do_OPTIONS = _deny_method
    do_HEAD = _deny_method


def _handler(config: ProxyConfig, policy: DockerReadOnlyPolicy, token: str) -> type[DockerReadOnlyProxyHandler]:
    class ConfiguredHandler(DockerReadOnlyProxyHandler):
        pass

    ConfiguredHandler.config = config
    ConfiguredHandler.policy = policy
    ConfiguredHandler.bearer_token = token
    return ConfiguredHandler


def build_server(config: ProxyConfig) -> BoundedThreadingHTTPServer:
    token = _load_bearer_token(config.bearer_token_file)
    policy = DockerReadOnlyPolicy(
        api_version=config.api_version,
        max_page_size=config.max_page_size,
        max_log_window_seconds=config.max_log_window_seconds,
        max_event_window_seconds=config.max_event_window_seconds,
    )
    server = BoundedThreadingHTTPServer(
        (config.bind_host, config.bind_port),
        _handler(config, policy, token),
        max_concurrency=config.max_concurrency,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(config.tls_cert_file, config.tls_key_file)
    except (OSError, ssl.SSLError) as exc:
        server.server_close()
        raise ValueError("failed to load Docker read-only proxy TLS certificate or key") from exc
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    config = ProxyConfig.from_env()
    server = build_server(config)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
