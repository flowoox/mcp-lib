from __future__ import annotations

import threading
import time
from collections.abc import Callable

from pydantic import Field

from .operations import StrictModel


class QueryBudgetExceeded(RuntimeError):
    """Raised before a diagnostic query can exceed its configured load budget."""


class QueryBudgetLimits(StrictModel):
    """Hard per-tool-call limits shared by paged and fan-out diagnostics."""

    max_requests: int = Field(default=8, ge=1, le=1_000)
    max_items: int = Field(default=500, ge=1, le=100_000)
    max_response_bytes: int = Field(default=1_048_576, ge=1_024, le=104_857_600)
    max_fan_out: int = Field(default=8, ge=1, le=1_000)
    total_timeout_seconds: float = Field(default=15.0, ge=0.1, le=3_600.0)


class QueryBudgetSnapshot(StrictModel):
    requests_used: int
    requests_remaining: int
    items_used: int
    items_remaining: int
    response_bytes_used: int
    response_bytes_remaining: int
    fan_out_used: int
    fan_out_remaining: int
    elapsed_seconds: float
    timeout_seconds_remaining: float


class QueryBudget:
    """Thread-safe, monotonic budget for one agent-facing operation.

    A budget is intentionally not a global quota. Deployments should combine it
    with upstream identity limits. This object bounds the work caused by one MCP
    invocation, including all pagination and downstream fan-out performed for it.
    """

    def __init__(
        self,
        limits: QueryBudgetLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._clock = clock
        self._started_at = clock()
        self._requests = 0
        self._items = 0
        self._response_bytes = 0
        self._fan_out = 0
        self._lock = threading.Lock()

    def _elapsed_unlocked(self) -> float:
        return max(0.0, self._clock() - self._started_at)

    def _require_time_unlocked(self) -> float:
        remaining = self.limits.total_timeout_seconds - self._elapsed_unlocked()
        if remaining <= 0:
            raise QueryBudgetExceeded("query budget total timeout exhausted")
        return remaining

    @staticmethod
    def _require_non_negative(name: str, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")

    @staticmethod
    def _require_positive(name: str, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")

    def reserve_request(self, *, requests: int = 1, fan_out: int = 1) -> None:
        """Reserve backend work before starting it; failed reservations consume nothing."""

        self._require_positive("requests", requests)
        self._require_positive("fan_out", fan_out)
        with self._lock:
            self._require_time_unlocked()
            if self._requests + requests > self.limits.max_requests:
                raise QueryBudgetExceeded("query budget request limit exceeded")
            if self._fan_out + fan_out > self.limits.max_fan_out:
                raise QueryBudgetExceeded("query budget fan-out limit exceeded")
            self._requests += requests
            self._fan_out += fan_out

    def record_response(self, *, items: int, response_bytes: int) -> None:
        """Account for a response before it is exposed to the calling tool."""

        self._require_non_negative("items", items)
        self._require_non_negative("response_bytes", response_bytes)
        with self._lock:
            self._require_time_unlocked()
            if self._items + items > self.limits.max_items:
                raise QueryBudgetExceeded("query budget item limit exceeded")
            if self._response_bytes + response_bytes > self.limits.max_response_bytes:
                raise QueryBudgetExceeded("query budget response-byte limit exceeded")
            self._items += items
            self._response_bytes += response_bytes

    def remaining_timeout(self, requested_seconds: float | None = None) -> float:
        """Return a timeout clipped to the remaining total operation deadline."""

        if requested_seconds is not None and requested_seconds <= 0:
            raise ValueError("requested_seconds must be greater than zero")
        with self._lock:
            remaining = self._require_time_unlocked()
        return remaining if requested_seconds is None else min(remaining, requested_seconds)

    def snapshot(self) -> QueryBudgetSnapshot:
        with self._lock:
            elapsed = self._elapsed_unlocked()
            timeout_remaining = max(0.0, self.limits.total_timeout_seconds - elapsed)
            return QueryBudgetSnapshot(
                requests_used=self._requests,
                requests_remaining=max(0, self.limits.max_requests - self._requests),
                items_used=self._items,
                items_remaining=max(0, self.limits.max_items - self._items),
                response_bytes_used=self._response_bytes,
                response_bytes_remaining=max(
                    0, self.limits.max_response_bytes - self._response_bytes
                ),
                fan_out_used=self._fan_out,
                fan_out_remaining=max(0, self.limits.max_fan_out - self._fan_out),
                elapsed_seconds=elapsed,
                timeout_seconds_remaining=timeout_remaining,
            )
