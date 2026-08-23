import pytest
from pydantic import ValidationError

from security_audit_mcp.config import Settings


def test_defaults_are_local_and_bounded() -> None:
    settings = Settings()
    assert settings.mcp_host == "127.0.0.1"
    assert settings.mcp_port == 8090
    assert settings.security_audit_max_evidence == 200
    assert settings.security_audit_budget_timeout_seconds == 10.0


def test_evidence_limit_cannot_exceed_schema_bound() -> None:
    with pytest.raises(ValidationError):
        Settings(security_audit_max_evidence=201)
