from __future__ import annotations

import re
from typing import Any

from mcp_common.query_budget import QueryBudget
from mcp_common.read_only_connector import PageRequest, ReadOnlyConnector, ReadOnlyQuery

_EXIT_STATUS_RE = re.compile(r"\bExited\s*\((\d+)\)", re.IGNORECASE)


def _candidate_reasons(container: dict[str, Any]) -> tuple[int, list[str]] | None:
    state = str(container.get("state") or "").strip().casefold()
    status = str(container.get("status") or "").strip()
    status_folded = status.casefold()
    ranked_reasons: list[tuple[int, str]] = []

    if state == "dead":
        ranked_reasons.append((0, "state:dead"))
    if state == "restarting":
        ranked_reasons.append((1, "state:restarting"))
    if "unhealthy" in status_folded:
        ranked_reasons.append((2, "health:unhealthy"))

    exit_match = _EXIT_STATUS_RE.search(status)
    if state == "exited" and exit_match is not None and int(exit_match.group(1)) != 0:
        ranked_reasons.append((3, f"exit:nonzero:{exit_match.group(1)}"))
    if state == "paused":
        ranked_reasons.append((4, "state:paused"))

    if not ranked_reasons:
        return None
    ranked_reasons.sort(key=lambda item: (item[0], item[1]))
    return ranked_reasons[0][0], [reason for _, reason in ranked_reasons[:4]]


def select_diagnostic_candidates(
    containers: list[Any],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Select deterministic anomaly candidates from already-bounded aggregate inventory."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("diagnostic candidate limit must be a positive integer")

    ranked: list[tuple[int, str, dict[str, Any]]] = []
    for value in containers:
        if not isinstance(value, dict):
            continue
        container_id = str(value.get("id") or "")[:128]
        if not container_id:
            continue
        reason_result = _candidate_reasons(value)
        if reason_result is None:
            continue
        priority, reasons = reason_result
        names = value.get("names")
        name = ""
        if isinstance(names, list) and names:
            name = str(names[0])[:200]
        candidate = {
            "containerId": container_id,
            "name": name,
            "state": str(value.get("state") or "")[:50],
            "status": str(value.get("status") or "")[:300],
            "reasons": reasons,
        }
        ranked.append((priority, container_id, candidate))

    ranked.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in ranked[:limit]]


def _preflight_detail_capacity(
    budget: QueryBudget,
    *,
    requested_candidates: int,
    operator_max_candidates: int,
) -> None:
    if requested_candidates > operator_max_candidates:
        raise ValueError(
            "detail_limit exceeds DOCKER_DIAGNOSTIC_DETAIL_MAX_CANDIDATES"
        )
    required_requests = 1 + requested_candidates
    required_fan_out = 1 + requested_candidates
    if required_requests > budget.limits.max_requests:
        raise ValueError("query budget request limit cannot support requested diagnostic detail")
    if required_fan_out > budget.limits.max_fan_out:
        raise ValueError("query budget fan-out limit cannot support requested diagnostic detail")


async def collect_diagnostic_detail(
    connector: ReadOnlyConnector,
    budget: QueryBudget,
    *,
    include_stopped: bool,
    inventory_limit: int,
    detail_limit: int,
    operator_max_candidates: int,
) -> dict[str, Any]:
    """Aggregate first, then perform bounded one-shot stats fan-out for selected anomalies only."""

    _preflight_detail_capacity(
        budget,
        requested_candidates=detail_limit,
        operator_max_candidates=operator_max_candidates,
    )

    inventory = await connector.execute(
        ReadOnlyQuery(
            operation="docker.containers.list",
            parameters={"include_stopped": include_stopped},
            page=PageRequest(limit=inventory_limit),
            aggregated=True,
        ),
        budget,
    )
    candidates = select_diagnostic_candidates(inventory.items, limit=detail_limit)

    details: list[dict[str, Any]] = []
    for candidate in candidates:
        container_id = candidate["containerId"]
        stats = await connector.execute(
            ReadOnlyQuery(
                operation="docker.containers.stats",
                parameters={"container_id": container_id},
                page=PageRequest(limit=1),
                aggregated=True,
            ),
            budget,
        )
        if len(stats.items) != 1 or not isinstance(stats.items[0], dict):
            raise RuntimeError("docker.containers.stats returned an invalid normalized result")
        details.append({"candidate": candidate, "stats": stats.items[0]})

    return {
        "selection": {
            "strategy": "aggregate-first-deterministic-anomaly",
            "inventoryReturned": len(inventory.items),
            "inventoryTruncated": inventory.truncated,
            "selectedCount": len(candidates),
            "detailLimit": detail_limit,
            "operatorMaxCandidates": operator_max_candidates,
        },
        "details": details,
        "automaticLogsFetched": False,
        "automaticEventsFetched": False,
    }
