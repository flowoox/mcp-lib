from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from mcp_common.store import AtomicJsonStore


class OperationLedger:
    """Small idempotency ledger for controlled AD mutations."""

    def __init__(self, path: str | Path):
        self.store = AtomicJsonStore(path, default={"version": 1, "operations": {}})
        self._lock = RLock()

    def get(self, idempotency_key: str, fingerprint: str) -> dict[str, Any] | None:
        with self._lock:
            data = self.store.read()
            operations = data.get("operations", {})
            if not isinstance(operations, dict):
                raise RuntimeError("operation ledger is malformed")
            record = operations.get(idempotency_key)
            if record is None:
                return None
            if not isinstance(record, dict) or record.get("fingerprint") != fingerprint:
                raise ValueError("idempotency key was already used for a different operation")
            result = record.get("result")
            if not isinstance(result, dict):
                raise RuntimeError("operation ledger result is malformed")
            return result

    def record(
        self,
        idempotency_key: str,
        fingerprint: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            data = self.store.read()
            operations = data.get("operations", {})
            if not isinstance(operations, dict):
                operations = {}
            existing = operations.get(idempotency_key)
            if existing is not None:
                if not isinstance(existing, dict) or existing.get("fingerprint") != fingerprint:
                    raise ValueError("idempotency key was already used for a different operation")
                stored = existing.get("result")
                if not isinstance(stored, dict):
                    raise RuntimeError("operation ledger result is malformed")
                return stored
            operations[idempotency_key] = {
                "fingerprint": fingerprint,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "result": result,
            }
            data["version"] = 1
            data["operations"] = operations
            self.store.write(data)
            return result
