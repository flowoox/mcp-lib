from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from mcp_ad.audit import (
    datetime_to_ad_filetime,
    evaluate_domain_policy,
    evaluate_privileged_members,
    run_security_audit,
)
from mcp_ad.models import DirectoryObject, QueryResult, Severity


def test_weak_domain_policy_produces_explicit_findings() -> None:
    findings = evaluate_domain_policy(
        {
            "minPwdLength": 8,
            "pwdProperties": 0,
            "lockoutThreshold": 0,
            "pwdHistoryLength": 5,
        },
        minimum_password_length=14,
    )
    ids = {finding.check_id for finding in findings}
    assert {
        "AD-PASSWORD-MIN-LENGTH",
        "AD-PASSWORD-COMPLEXITY",
        "AD-LOCKOUT-DISABLED",
        "AD-PASSWORD-HISTORY",
    } <= ids


def test_strong_baseline_does_not_create_password_findings() -> None:
    findings = evaluate_domain_policy(
        {
            "minPwdLength": 16,
            "pwdProperties": 1,
            "lockoutThreshold": 10,
            "pwdHistoryLength": 24,
        },
        minimum_password_length=14,
    )
    assert findings == []


def test_privileged_nonexpiring_and_disabled_accounts_are_reported() -> None:
    groups = {
        "CN=Tier0,OU=Groups,DC=example,DC=internal": QueryResult(
            count=1,
            objects=[
                DirectoryObject(
                    distinguished_name="CN=Legacy Admin,OU=People,DC=example,DC=internal",
                    attributes={
                        "sAMAccountName": "legacy-admin",
                        "userAccountControl": 0x0002 | 0x10000,
                    },
                )
            ],
        )
    }
    findings = evaluate_privileged_members(groups)
    assert {finding.check_id for finding in findings} == {
        "AD-PRIVILEGED-DISABLED",
        "AD-PRIVILEGED-NONEXPIRING",
    }
    assert any(finding.severity == Severity.HIGH for finding in findings)


def test_ad_filetime_requires_timezone_aware_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        datetime_to_ad_filetime(datetime(2026, 1, 1))
    assert datetime_to_ad_filetime(datetime(2026, 1, 1, tzinfo=timezone.utc)) > 0


class FakeClient:
    settings = SimpleNamespace(
        ad_base_dn="DC=example,DC=internal",
        ad_min_password_length=14,
        ad_stale_days=90,
    )

    def get_domain_policy(self) -> QueryResult:
        return QueryResult(
            count=1,
            objects=[
                DirectoryObject(
                    distinguished_name="DC=example,DC=internal",
                    attributes={
                        "minPwdLength": 16,
                        "pwdProperties": 1,
                        "lockoutThreshold": 10,
                        "pwdHistoryLength": 24,
                    },
                )
            ],
        )

    def list_stale_enabled_users(self, *, stale_before_filetime: int) -> QueryResult:
        assert stale_before_filetime > 0
        return QueryResult(count=0, objects=[])

    def list_privileged_members(self) -> dict[str, QueryResult]:
        return {}


def test_full_audit_is_read_only_and_declares_scope_limitations() -> None:
    report = run_security_audit(
        FakeClient(),  # type: ignore[arg-type]
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
    assert report.scope == "DC=example,DC=internal"
    assert report.passed is True
    assert {finding.check_id for finding in report.findings} == {
        "AD-PRIVILEGED-SCOPE-NOT-CONFIGURED"
    }
    assert report.observations["limitations"]
