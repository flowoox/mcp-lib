from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any


class AtomicJsonStore:
    """Tiny process-safe-enough JSON store with atomic replacement.

    Each MCP service is intentionally single-process in the supplied container,
    so a local re-entrant lock plus an atomic rename is sufficient and keeps
    runtime configuration inspectable.
    """

    def __init__(self, path: str | Path, *, default: dict[str, Any] | None = None):
        self.path = Path(path)
        self.default = default or {}
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                return dict(self.default)
            try:
                value = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return dict(self.default)
            return value if isinstance(value, dict) else dict(self.default)

    def write(self, value: dict[str, Any]) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                dir=str(self.path.parent),
                text=True,
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp_name, 0o600)
                os.replace(temp_name, self.path)
            finally:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

    def update(self, **values: Any) -> dict[str, Any]:
        current = self.read()
        current.update(values)
        self.write(current)
        return current
