from __future__ import annotations

import json
import logging
from typing import Any

LOGGER = logging.getLogger("mcp_ad.audit")


def emit_audit_event(event: dict[str, Any]) -> None:
    """Emit one compact JSON event containing only explicit audit metadata."""

    LOGGER.info(json.dumps(event, sort_keys=True, separators=(",", ":"), default=str))
