from ad_mcp.baseline import BaselineProfile, Severity, evaluate_security_snapshot


def secure_snapshot() -> dict[str, object]:
    return {
        "domainMode": "Windows2016Domain",
        "forestMode": "Windows2016Forest",
        "minimumPasswordLength": 14,
        "passwordHistoryCount": 24,
        "complexityEnabled": True,
        "reversibleEncryptionEnabled": False,
        "lockoutThreshold": 10,
        "minimumPasswordAgeDays": 1.0,
        "maximumPasswordAgeDays": 42.0,
        "machineAccountQuota": 0,
        "recycleBinEnabled": True,
    }


def test_secure_snapshot_passes_default_profile() -> None:
    report = evaluate_security_snapshot(secure_snapshot())
    assert report.compliant is True
    assert report.findings == []


def test_evaluator_reports_high_value_ad_findings() -> None:
    snapshot = secure_snapshot()
    snapshot.update(
        {
            "domainMode": "Windows2012R2Domain",
            "minimumPasswordLength": 10,
            "passwordHistoryCount": 12,
            "complexityEnabled": False,
            "reversibleEncryptionEnabled": True,
            "lockoutThreshold": 0,
            "machineAccountQuota": 10,
            "recycleBinEnabled": False,
        }
    )
    report = evaluate_security_snapshot(snapshot)
    ids = {finding.id for finding in report.findings}
    assert report.compliant is False
    assert ids == {
        "AD-PASSWORD-MIN-LENGTH",
        "AD-PASSWORD-HISTORY",
        "AD-PASSWORD-COMPLEXITY",
        "AD-REVERSIBLE-PASSWORDS",
        "AD-LOCKOUT-DISABLED",
        "AD-MACHINE-ACCOUNT-QUOTA",
        "AD-RECYCLE-BIN",
        "AD-DOMAIN-FUNCTIONAL-LEVEL",
    }
    reversible = next(item for item in report.findings if item.id == "AD-REVERSIBLE-PASSWORDS")
    assert reversible.severity == Severity.CRITICAL


def test_baseline_thresholds_are_caller_selectable() -> None:
    snapshot = secure_snapshot()
    snapshot["minimumPasswordLength"] = 12
    profile = BaselineProfile(minimum_password_length=12)
    report = evaluate_security_snapshot(snapshot, profile)
    assert "AD-PASSWORD-MIN-LENGTH" not in {finding.id for finding in report.findings}
