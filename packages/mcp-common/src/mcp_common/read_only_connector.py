from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from pydantic import Field, field_validator

from .operations import StrictModel
from .query_budget import QueryBudget, QueryBudgetExceeded


class ReadOnlyConnectorError(RuntimeError):
    """Base error for a rejected or failed read-only connector query."""


class ReadOnlyConnectorTimeout(ReadOnlyConnectorError, TimeoutError):
    """Raised when queueing or upstream work exceeds the bounded timeout."""


class PageRequest(StrictModel):
    limit: int = Field(default=50, ge=1, le=10_000)
    cursor: str | None = Field(default=None, min_length=1, max_length=1_024)


class SampleRequest(StrictModel):
    size: int = Field(ge=1, le=10_000)
    strategy: Literal["head", "even"] = "even"


class ReadOnlyQuery(StrictModel):
    """Provider-neutral query envelope passed only to an allowlisted adapter operation."""

    operation: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    page: PageRequest = Field(default_factory=PageRequest)
    sample: SampleRequest | None = None
    fan_out: int = Field(default=1, ge=1, le=1_000)
    aggregated: bool = True


class CacheHint(StrictModel):
    max_age_seconds: int = Field(default=0, ge=0, le=86_400)
    stale_while_revalidate_seconds: int = Field(default=0, ge=0, le=86_400)
    scope: Literal["request", "operation", "backend"] = "operation"


class ReadOnlyPage(StrictModel):
    items: list[Any] = Field(default_factory=list)
    next_cursor: str | None = Field(default=None, min_length=1, max_length=1_024)
    truncated: bool = False
    sampled: bool = False
    payload_bytes: int = Field(ge=0)
    cache_hint: CacheHint | None = None


class ReadOnlyConnectorPolicy(StrictModel):
    """Static server-load policy for one provider adapter."""

    connector_name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    allowed_operations: frozenset[str] = Field(min_length=1)
    require_read_only_backend: bool = True
    max_page_size: int = Field(default=100, ge=1, le=10_000)
    max_sample_size: int = Field(default=100, ge=1, le=10_000)
    request_timeout_seconds: float = Field(default=10.0, ge=0.1, le=600.0)
    max_response_bytes: int = Field(default=1_048_576, ge=1_024, le=104_857_600)
    max_concurrency: int = Field(default=2, ge=1, le=64)
    rate_limit_per_second: float = Field(default=4.0, gt=0.0, le=10_000.0)
    aggregate_before_fan_out: bool = True
    default_cache_max_age_seconds: int = Field(default=0, ge=0, le=86_400)

    @field_validator("allowed_operations")
    @classmethod
    def validate_operations(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if not value or len(value) > 128:
                raise ValueError("allowed operation names must contain 1-128 characters")
            if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in value):
                raise ValueError("allowed operation names must use lowercase letters, digits, '.', '_', or '-'")
        return values


class ReadOnlyTransport(Protocol):
    """Service-specific adapter boundary; URLs and credentials stay behind it."""

    @property
    def read_only(self) -> bool: ...

    async def query(
        self,
        query: ReadOnlyQuery,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> ReadOnlyPage: ...


class ReadOnlyConnector:
    """Enforce read-only, budget, pagination, sampling and load limits centrally."""

    def __init__(self, policy: ReadOnlyConnectorPolicy, transport: ReadOnlyTransport) -> None:
        if policy.require_read_only_backend and getattr(transport, "read_only", False) is not True:
            raise ValueError("connector policy requires an explicitly read-only backend transport")
        self.policy = policy
        self.transport = transport
        self._semaphore = asyncio.Semaphore(policy.max_concurrency)
        self._rate_lock = asyncio.Lock()
        self._next_request_at = 0.0

    def _validate_query(self, query: ReadOnlyQuery) -> None:
        if query.operation not in self.policy.allowed_operations:
            raise PermissionError("connector operation is not in the explicit read-only allowlist")
        if query.page.limit > self.policy.max_page_size:
            raise ValueError(
                f"page limit exceeds connector maximum of {self.policy.max_page_size}"
            )
        if query.sample is not None:
            if query.sample.size > self.policy.max_sample_size:
                raise ValueError(
                    f"sample size exceeds connector maximum of {self.policy.max_sample_size}"
                )
            if query.sample.size > query.page.limit:
                raise ValueError("sample size cannot exceed the requested page limit")
        if self.policy.aggregate_before_fan_out and query.fan_out > 1 and not query.aggregated:
            raise PermissionError("fan-out requires an aggregate-first query plan")

    async def _wait_for_rate_slot(self) -> None:
        interval = 1.0 / self.policy.rate_limit_per_second
        async with self._rate_lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            delay = max(0.0, self._next_request_at - now)
            if delay:
                await asyncio.sleep(delay)
            started = loop.time()
            self._next_request_at = max(self._next_request_at, started) + interval

    @staticmethod
    def _sample(items: list[Any], request: SampleRequest) -> list[Any]:
        if len(items) <= request.size:
            return items
        if request.strategy == "head":
            return items[: request.size]
        if request.size == 1:
            return [items[0]]
        last = len(items) - 1
        indexes = [math.floor(index * last / (request.size - 1)) for index in range(request.size)]
        return [items[index] for index in indexes]

    async def execute(self, query: ReadOnlyQuery, budget: QueryBudget) -> ReadOnlyPage:
        self._validate_query(query)
        capacity = budget.snapshot()
        if query.page.limit > capacity.items_remaining:
            raise QueryBudgetExceeded(
                "requested page limit exceeds the remaining query-budget item capacity"
            )
        if capacity.response_bytes_remaining <= 0:
            raise QueryBudgetExceeded("query budget has no remaining response-byte capacity")
        budget.reserve_request(fan_out=query.fan_out)
        response_byte_limit = min(
            self.policy.max_response_bytes,
            capacity.response_bytes_remaining,
        )
        total_timeout = budget.remaining_timeout(self.policy.request_timeout_seconds)
        try:
            async with asyncio.timeout(total_timeout):
                async with self._semaphore:
                    await self._wait_for_rate_slot()
                    upstream_timeout = budget.remaining_timeout(
                        self.policy.request_timeout_seconds
                    )
                    page = await self.transport.query(
                        query,
                        timeout_seconds=upstream_timeout,
                        max_response_bytes=response_byte_limit,
                    )
        except TimeoutError as exc:
            raise ReadOnlyConnectorTimeout(
                f"{self.policy.connector_name} read-only query exceeded its timeout"
            ) from exc

        page = ReadOnlyPage.model_validate(page)
        if len(page.items) > query.page.limit:
            raise ReadOnlyConnectorError("backend returned more items than the requested page limit")
        if page.payload_bytes > response_byte_limit:
            raise ReadOnlyConnectorError("backend response exceeded the connector byte limit")
        budget.record_response(items=len(page.items), response_bytes=page.payload_bytes)

        updates: dict[str, Any] = {}
        if query.sample is not None and len(page.items) > query.sample.size:
            updates["items"] = self._sample(page.items, query.sample)
            updates["sampled"] = True
            updates["truncated"] = True
        if page.cache_hint is None:
            updates["cache_hint"] = CacheHint(
                max_age_seconds=self.policy.default_cache_max_age_seconds
            )
        return page.model_copy(update=updates) if updates else page


def redacted_connector_metadata(
    policy: ReadOnlyConnectorPolicy,
    *,
    backend_kind: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return capabilities without leaking connector URLs, credentials or topology."""

    metadata: dict[str, Any] = {
        "backend_kind": backend_kind,
        "backend_mode": "read_only",
        "allowed_operations": sorted(policy.allowed_operations),
        "max_page_size": policy.max_page_size,
        "max_sample_size": policy.max_sample_size,
        "request_timeout_seconds": policy.request_timeout_seconds,
        "max_response_bytes": policy.max_response_bytes,
        "max_concurrency": policy.max_concurrency,
        "rate_limit_per_second": policy.rate_limit_per_second,
        "aggregate_before_fan_out": policy.aggregate_before_fan_out,
        "cache_max_age_seconds": policy.default_cache_max_age_seconds,
    }
    if extra:
        metadata.update(extra)
    return metadata
