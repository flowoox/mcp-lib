import pytest

from ad_mcp.ledger import OperationLedger


def test_ledger_replays_same_operation(tmp_path) -> None:
    ledger = OperationLedger(tmp_path / "operations.json")
    result = {"status": "succeeded", "changed": True}

    assert ledger.get("joiner:alice:001", "fingerprint-a") is None
    assert ledger.record("joiner:alice:001", "fingerprint-a", result) == result
    assert ledger.get("joiner:alice:001", "fingerprint-a") == result
    assert ledger.record("joiner:alice:001", "fingerprint-a", {"ignored": True}) == result


def test_ledger_rejects_key_reuse_for_different_operation(tmp_path) -> None:
    ledger = OperationLedger(tmp_path / "operations.json")
    ledger.record("joiner:alice:001", "fingerprint-a", {"status": "succeeded"})

    with pytest.raises(ValueError, match="different operation"):
        ledger.get("joiner:alice:001", "fingerprint-b")
    with pytest.raises(ValueError, match="different operation"):
        ledger.record("joiner:alice:001", "fingerprint-b", {"status": "succeeded"})
