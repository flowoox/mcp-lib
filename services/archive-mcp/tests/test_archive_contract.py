from archive_mcp.contract import CONTRACT_NAME, capabilities


def test_archive_speaks_the_same_acquisition_contract_as_soulseek() -> None:
    """The pipeline drives both connectors through one code path.

    A different contract name or major version here would force the
    orchestrator to special-case the fallback, which is exactly what the
    shared contract exists to avoid.
    """
    result = capabilities()
    assert result["contract"] == {
        "name": CONTRACT_NAME,
        "version": "1.2",
        "major": 1,
    }
    assert CONTRACT_NAME == "flowoox.music-acquisition"
    assert result["role"] == "acquisition-provider"
    assert result["artifact_schemes"] == ["shared-volume"]
    assert result["features"]["rights_validation"] is True
    assert result["features"]["idempotent_queue"] is True
    assert result["features"]["status_polling"] is True


def test_contract_advertises_what_this_source_adds_over_soulseek() -> None:
    features = capabilities()["features"]
    assert features["checksum_verification"] is True
    assert features["open_license_gate"] is True
    # No account exists for archive.org, so there is no login state to report.
    assert features["login_state_reporting"] is False


def test_tool_names_match_the_soulseek_shape() -> None:
    tools = set(capabilities()["tools"])
    for shared in (
        "get_capabilities",
        "health",
        "search_album",
        "get_album_candidate",
        "queue_album_folder",
        "get_download_batch",
        "wait_for_download",
    ):
        assert shared in tools
