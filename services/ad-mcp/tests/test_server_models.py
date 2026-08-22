from uuid import uuid4

import pytest
from pydantic import ValidationError

from ad_mcp.server import IdentityInput, _observe_response


def test_identity_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        IdentityInput(identity="alice\nGet-ADUser")


def test_observe_response_preserves_correlation_and_cannot_claim_change() -> None:
    correlation_id = str(uuid4())
    response = _observe_response(
        "ad.domain.summary",
        correlation_id,
        {"dnsRoot": "example.invalid"},
    )
    assert response["phase"] == "observe"
    assert response["changed"] is False
    assert response["context"]["correlation_id"] == correlation_id
    assert response["audit"]["context"]["correlation_id"] == correlation_id
    assert response["audit"]["risk"] == "read_only"


def test_observe_response_rejects_invalid_correlation_id() -> None:
    with pytest.raises(ValueError, match="UUID"):
        _observe_response("ad.domain.summary", "not-a-uuid", {})
