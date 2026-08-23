from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import (
    AuditEvaluation,
    AuditSummary,
    ControlResult,
    ControlState,
    EvidenceFact,
    EvidenceKind,
    Severity,
    json_safe_value,
)


@dataclass(frozen=True)
class Rule:
    control_id: str
    kind: EvidenceKind
    title: str
    severity: Severity
    expected: str
    remediation: str
    passes: Callable[[bool | int], bool]


RULES = (
    Rule(
        "SEC-AD-001",
        EvidenceKind.AD_REPLICATION_FAILURES,
        "Active Directory replication is healthy",
        Severity.HIGH,
        "0 replication failures",
        "Investigate replication partners, DNS, time synchronization and AD DS event logs before making directory changes.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value == 0,
    ),
    Rule(
        "SEC-AD-002",
        EvidenceKind.AD_SECURE_CHANNEL_HEALTHY,
        "Active Directory secure channel is healthy",
        Severity.HIGH,
        "secure channel healthy = true",
        "Repair the machine secure channel using an approved AD runbook and independently verify trust afterwards.",
        lambda value: value is True,
    ),
    Rule(
        "SEC-NET-001",
        EvidenceKind.NETWORK_FAILED_CHECKS,
        "Required network diagnostics succeed",
        Severity.MEDIUM,
        "0 failed allowlisted checks",
        "Inspect the failed authorized targets, routing, DNS and firewall path without widening probe scope.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value == 0,
    ),
    Rule(
        "SEC-FG-001",
        EvidenceKind.FORTIGATE_HA_HEALTHY,
        "FortiGate HA reports healthy state",
        Severity.HIGH,
        "HA healthy = true",
        "Review cluster membership, synchronization and monitored interfaces before changing policy state.",
        lambda value: value is True,
    ),
    Rule(
        "SEC-FG-002",
        EvidenceKind.FORTIGATE_PERMISSIVE_POLICY_COUNT,
        "No allowlisted policy analysis flags overly permissive rules",
        Severity.HIGH,
        "0 overly permissive policies",
        "Review each flagged policy individually and narrow source, destination, service or security inspection through an approved change.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value == 0,
    ),
    Rule(
        "SEC-ENTRA-001",
        EvidenceKind.ENTRA_CONDITIONAL_ACCESS_ENABLED_COUNT,
        "At least one Conditional Access policy is enabled",
        Severity.HIGH,
        ">= 1 enabled Conditional Access policy",
        "Review tenant Conditional Access design and deploy an approved baseline with break-glass exclusions and staged validation.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value >= 1,
    ),
    Rule(
        "SEC-WIN-001",
        EvidenceKind.WINDOWS_REBOOT_PENDING,
        "Windows host has no pending reboot",
        Severity.MEDIUM,
        "reboot pending = false",
        "Schedule a controlled reboot if change context permits and verify services and cluster roles after restart.",
        lambda value: value is False,
    ),
    Rule(
        "SEC-WIN-002",
        EvidenceKind.WINDOWS_CRITICAL_EVENT_COUNT,
        "Windows bounded critical-event window is clear",
        Severity.HIGH,
        "0 critical events in the selected bounded window",
        "Inspect the bounded event evidence and correlate it with service, update and infrastructure health before remediation.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value == 0,
    ),
    Rule(
        "SEC-WIN-003",
        EvidenceKind.WINDOWS_FAILED_SERVICE_COUNT,
        "Required Windows services are healthy",
        Severity.HIGH,
        "0 failed required services",
        "Investigate only the allowlisted required services and their dependencies before considering a controlled restart.",
        lambda value: isinstance(value, int) and not isinstance(value, bool) and value == 0,
    ),
)

_RULE_BY_KIND = {rule.kind: rule for rule in RULES}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _latest_facts(facts: list[EvidenceFact]) -> tuple[list[EvidenceFact], int]:
    latest: dict[tuple[EvidenceKind, str], EvidenceFact] = {}
    stale = 0
    for fact in facts:
        key = (fact.kind, fact.subject.casefold())
        current = latest.get(key)
        if current is None:
            latest[key] = fact
            continue
        if fact.observed_at > current.observed_at:
            latest[key] = fact
            stale += 1
            continue
        if fact.observed_at < current.observed_at:
            stale += 1
            continue
        if fact.value != current.value or fact.source_operation != current.source_operation:
            raise ValueError(
                f"ambiguous evidence for {fact.kind.value} on {fact.subject}: equal timestamps conflict"
            )
        stale += 1
    return list(latest.values()), stale


def evaluate_evidence(
    facts: list[EvidenceFact],
    *,
    include_passed: bool = False,
) -> AuditEvaluation:
    latest, stale = _latest_facts(facts)
    findings: list[ControlResult] = []
    passed: list[ControlResult] = []

    for fact in latest:
        rule = _RULE_BY_KIND[fact.kind]
        value = json_safe_value(fact.value)
        state = ControlState.PASSED if rule.passes(value) else ControlState.FAILED
        result = ControlResult(
            control_id=rule.control_id,
            title=rule.title,
            severity=rule.severity,
            state=state,
            source=fact.source,
            subject=fact.subject,
            source_operation=fact.source_operation,
            observed_at=fact.observed_at,
            observed_value=value,
            expected=rule.expected,
            remediation=rule.remediation if state == ControlState.FAILED else None,
        )
        if state == ControlState.FAILED:
            findings.append(result)
        elif include_passed:
            passed.append(result)

    def ordering(item: ControlResult) -> tuple[int, str, str]:
        return (
            _SEVERITY_ORDER[item.severity],
            item.control_id,
            item.subject.casefold(),
        )

    findings.sort(key=ordering)
    passed.sort(key=ordering)
    by_severity = {severity: 0 for severity in Severity}
    for finding in findings:
        by_severity[finding.severity] += 1

    return AuditEvaluation(
        summary=AuditSummary(
            evaluated_controls=len(latest),
            passed_controls=len(latest) - len(findings),
            failed_controls=len(findings),
            stale_facts_ignored=stale,
            by_severity=by_severity,
        ),
        findings=findings,
        passed=passed,
    )


def rule_catalog() -> list[dict[str, str]]:
    return [
        {
            "controlId": rule.control_id,
            "evidenceKind": rule.kind.value,
            "title": rule.title,
            "severity": rule.severity.value,
            "expected": rule.expected,
        }
        for rule in RULES
    ]
