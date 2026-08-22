from __future__ import annotations

import json
import logging
from typing import Any

LOGGER = logging.getLogger("mcp_ad.audit")


def emit_audit_event(event: dict[str, Any]) -> None:
    """Emit one compact JSON event.

    Callers pass only explicit metadata. Directory objects, credentials and
    bind settings are intentionally not accepted by this helper.
    """

    LOGGER.info(json.dumps(event, sort_keys=True, separators=(",", ":"), default=str))
