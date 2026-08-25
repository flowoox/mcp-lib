from traxx_mcp.contract import CONTRACT_NAME, capabilities


def test_library_import_contract_is_versioned_and_normalizes_metadata() -> None:
    result = capabilities()
    assert result["contract"] == {
        "name": CONTRACT_NAME,
        "version": "1.7",
        "major": 1,
    }
    assert result["role"] == "library-target"
    assert result["artifact_schemes"] == ["shared-volume"]
    assert result["features"]["metadata_normalization"] is True
    assert result["features"]["cover_embedding"] is True
    assert result["features"]["idempotent_import"] is True
    assert result["features"]["fail_closed_malware_scan"] is True
    assert result["features"]["malware_quarantine"] is True
    assert "scan_album_folder" in result["tools"]
    assert result["features"]["retryable_partial_import"] is True
    assert "get_capabilities" in result["tools"]


def test_contract_announces_playlist_management_and_actors() -> None:
    result = capabilities()
    assert result["features"]["playlist_management"] is True
    assert result["features"]["actor_scoped_requests"] is True
    assert result["features"]["managed_user_playlists"] is True
    for tool in (
        "list_playlists",
        "get_playlist",
        "update_playlist",
        "remove_playlist_tracks",
        "replace_playlist_tracks",
        "configure_traxx_actor",
        "remove_traxx_actor",
        "list_traxx_actors",
    ):
        assert tool in result["tools"], tool
    # The pre-1.4 surface must survive untouched for existing orchestrators.
    for tool in ("create_playlist", "add_playlist_tracks", "list_liked"):
        assert tool in result["tools"], tool
