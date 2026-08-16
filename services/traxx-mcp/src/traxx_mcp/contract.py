from __future__ import annotations

from typing import Any

from . import __version__

CONTRACT_NAME = "flowoox.music-library-import"
CONTRACT_VERSION = "1.3"


def capabilities() -> dict[str, Any]:
    return {
        "contract": {
            "name": CONTRACT_NAME,
            "version": CONTRACT_VERSION,
            "major": 1,
        },
        "service": {"name": "mcp-traxx", "version": __version__},
        "role": "library-target",
        "artifact_schemes": ["shared-volume"],
        "features": {
            "metadata_normalization": True,
            "cover_download": True,
            "cover_embedding": True,
            "tus_upload": True,
            "album_import": True,
            "dry_run": True,
            "rights_validation": True,
            "upload_diagnostics": True,
            "idempotent_import": True,
            "retryable_partial_import": True,
            "search_based_lookup": True,
            "proxy_headers": True,
        },
        "tools": [
            "get_capabilities",
            "configure_traxx",
            "get_configuration",
            "health",
            "list_tracks",
            "list_albums",
            "list_artists",
            "list_liked",
            "search_library",
            "inspect_local_track",
            "diagnose_upload",
            "import_album_folder",
            "import_external_metadata",
            "create_playlist",
            "add_playlist_tracks",
        ],
    }
