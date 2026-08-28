from __future__ import annotations

from typing import Any

from . import __version__

CONTRACT_NAME = "flowoox.music-acquisition"
CONTRACT_VERSION = "1.2"


def capabilities() -> dict[str, Any]:
    return {
        "contract": {
            "name": CONTRACT_NAME,
            "version": CONTRACT_VERSION,
            "major": 1,
        },
        "service": {"name": "mcp-soulseek", "version": __version__},
        "role": "acquisition-provider",
        "artifact_schemes": ["shared-volume"],
        "features": {
            "complete_album_folder": True,
            "multi_disc": True,
            "lossless_quality_gate": True,
            "lossy_minimum_bitrate": True,
            "rights_validation": True,
            "status_polling": True,
            "idempotent_queue": True,
            "expected_track_count_validation": True,
            "login_state_reporting": True,
            "recoverable_retry_archive": True,
        },
        "audio_formats": {
            "lossless": ["flac", "wav", "alac", "aiff", "aif", "ape", "wv"],
            "lossy": ["mp3", "m4a", "aac", "ogg", "opus"],
        },
        "tools": [
            "get_capabilities",
            "configure_slskd",
            "get_configuration",
            "health",
            "search_album",
            "get_album_candidate",
            "queue_album_folder",
            "cancel_download_batch",
            "archive_download_folder",
            "list_downloads",
            "get_download_batch",
            "wait_for_download",
            "browse_user",
        ],
    }
