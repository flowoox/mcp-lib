from soulseek_mcp.contract import CONTRACT_NAME, capabilities


def test_acquisition_contract_is_versioned_and_lossless_capable() -> None:
    result = capabilities()
    assert result["contract"] == {
        "name": CONTRACT_NAME,
        "version": "1.0",
        "major": 1,
    }
    assert result["role"] == "acquisition-provider"
    assert result["artifact_schemes"] == ["shared-volume"]
    assert result["features"]["lossless_quality_gate"] is True
    assert "flac" in result["audio_formats"]["lossless"]
    assert "get_capabilities" in result["tools"]
