from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from security_audit_mcp.models import EvidenceBatch, EvidenceFact


def fact(**overrides):
    data = {
        "kind": "ad.replication_failures",
        "source": "active_directory",
        "subject": "dc01.example.test",
        "source_operation": "ad.replication.observe",
        "observed_at": datetime(2026, 8, 23, 8, 0, tzinfo=timezone.utc),
        "int_value": 0,
    }
    data.update(overrides)
    return EvidenceFact(**data)


def test_evidence_requires_matching_source_and_typed_value() -> None:
    with pytest.raises(ValidationError):
        fact(source="windows")
    with pytest.raises(ValidationError):
        fact(bool_value=True)
    with pytest.raises(ValidationError):
        EvidenceFact(
            kind="windows.reboot_pending",
            source="windows",
            subject="srv01",
            source_operation="windows.host.observe",
            observed_at=datetime.now(timezone.utc),
            int_value=0,
        )


def test_evidence_requires_timezone_and_batch_is_bounded() -> None:
    with pytest.raises(ValidationError):
        fact(observed_at=datetime(2026, 8, 23, 8, 0))
    with pytest.raises(ValidationError):
        EvidenceBatch(facts=[fact()] * 201)
