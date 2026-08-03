from traxx_mcp.contract import CONTRACT_NAME, capabilities


def test_library_import_contract_is_versioned_and_normalizes_metadata() -> None:
    result = capabilities()
    assert result["contract"] == {
        "name": CONTRACT_NAME,
        "version": "1.0",
        "major": 1,
    }
    assert result["role"] == "library-target"
    assert result["artifact_schemes"] == ["shared-volume"]
    assert result["features"]["metadata_normalization"] is True
    assert result["features"]["cover_embedding"] is True
    assert "get_capabilities" in result["tools"]
