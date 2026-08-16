from __future__ import annotations

from typing import Any


def capabilities() -> dict[str, Any]:
    return {
        "contract": "flowoox.example",
        "version": "1.0.0",
        "capabilities": [
            {
                "id": "example.echo",
                "risk": "read",
                "description": "Return validated example input.",
            }
        ],
    }
