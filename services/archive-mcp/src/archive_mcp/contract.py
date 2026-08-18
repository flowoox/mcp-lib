from __future__ import annotations

from typing import Any

from . import __version__

# Deliberately the same contract as the Soulseek connector: the orchestrator
# drives both through search -> candidates -> queue -> poll, and a second name
# would mean a second code path in the pipeline for no gain.
CONTRACT_NAME = "flowoox.music-acquisition"
CONTRACT_VERSION = "1.2"


def capabilities() -> dict[str, Any]:
    return {
        "contract": {
            "name": CONTRACT_NAME,
            "version": CONTRACT_VERSION,
            "major": 1,
        },
        "service": {"name": "mcp-archive", "version": __version__},
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
            "login_state_reporting": False,
            # What this source has and Soulseek does not: every file comes with
            # an md5 from the item metadata, and every item states its licence.
            "checksum_verification": True,
            "open_license_gate": True,
        },
        "audio_formats": {
            "lossless": ["flac", "wav", "aiff", "aif"],
            "lossy": ["mp3", "m4a", "aac", "ogg", "opus"],
        },
        "tools": [
            "get_capabilities",
            "configure_archive",
            "get_configuration",
            "health",
            "search_album",
            "get_album_candidate",
            "queue_album_folder",
            "list_downloads",
            "get_download_batch",
            "wait_for_download",
        ],
    }
