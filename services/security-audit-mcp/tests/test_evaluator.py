from datetime import datetime, timedelta, timezone

import pytest

from security_audit_mcp.evaluator import evaluate_evidence, rule_catalog
from security_audit_mcp.models import EvidenceFact

BASE = datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc)


def evidence(kind, source, value, *, subject="target", at=BASE, operation="source.observe"):
    payload = {
        "kind": kind,
        "source": source,
        "subject": subject,
        "source_operation": operation,
        "observed_at": at,
    }
    if isinstance(value, bool):
        payload["bool_value"] = value
    else:
        payload["int_value"] = value
    return EvidenceFact(**payload)


def test_evaluator_returns_only_failed_controls_by_default() -> None:
    result = evaluate_evidence(
        [
            evidence("ad.replication_failures", "active_directory", 2, subject="dc01"),
            evidence("fortigate.ha_healthy", "fortigate", True, subject="cluster-a"),
            evidence("windows.reboot_pending", "windows", True, subject="srv01"),
            evidence("entra.conditional_access_enabled_count", "entra", 0, subject="tenant"),
        ]
    )
    assert result.summary.evaluated_controls == 4
    assert result.summary.failed_controls == 3
    assert result.summary.passed_controls == 1
    assert [item.control_id for item in result.findings] == [
        "SEC-AD-001",
        "SEC-ENTRA-001",
        "SEC-WIN-001",
    ]
    assert result.passed == []


def test_latest_evidence_wins_and_stale_count_is_reported() -> None:
    result = evaluate_evidence(
        [
            evidence("windows.reboot_pending", "windows", True, at=BASE),
            evidence(
                "windows.reboot_pending",
                "windows",
                False,
                at=BASE + timedelta(minutes=1),
            ),
        ],
        include_passed=True,
    )
    assert result.summary.stale_facts_ignored == 1
    assert result.summary.failed_controls == 0
    assert result.passed[0].observed_value is False


def test_equal_timestamp_conflict_fails_closed() -> None:
    with pytest.raises(ValueError, match="ambiguous evidence"):
        evaluate_evidence(
            [
                evidence("fortigate.ha_healthy", "fortigate", True),
                evidence("fortigate.ha_healthy", "fortigate", False),
            ]
        )


def test_catalog_is_fixed_and_has_unique_controls() -> None:
    catalog = rule_catalog()
    ids = [item["controlId"] for item in catalog]
    assert len(ids) == len(set(ids))
    assert "SEC-FG-002" in ids
    assert "SEC-WIN-003" in ids
