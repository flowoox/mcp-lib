from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Any

from mcp.server.fastmcp import FastMCP

from .candidate_store import CandidateStore
from .config import SoulseekSettings, get_soulseek_settings
from .rights import validate_rights
from .slskd import SlskdClient
from .utils import safe_relative_destination, stable_id

LOGGER = logging.getLogger(__name__)


def create_server(settings: SoulseekSettings | None = None) -> FastMCP:
    settings = settings or get_soulseek_settings()
    store = CandidateStore(settings.state_db)
    client = SlskdClient(
        base_url=settings.slskd_url,
        api_key=settings.slskd_api_key,
        search_timeout=settings.slskd_search_timeout,
        result_limit=settings.slskd_result_limit,
        minimum_tracks=settings.slskd_minimum_tracks,
        preferred_formats=settings.preferred_audio_formats,
    )
    mcp = FastMCP(
        "Soulseek Album MCP",
        instructions=(
            "Searches slskd for complete album folders and queues the full remote folder. "
            "Queueing is a side effect and requires an explicit rights assertion."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    async def health() -> dict[str, Any]:
        """Check whether the configured slskd API is reachable."""
        return await client.health()

    @mcp.tool()
    async def search_album(
        artist: str,
        album: str,
        max_candidates: int = 10,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Search for complete album folders, including CD1/Disc 2 subfolders."""
        search_id, candidates, _raw = await client.search_album(
            artist=artist,
            album=album,
            timeout_seconds=timeout_seconds,
            max_candidates=max_candidates,
        )
        for candidate in candidates:
            store.save(candidate)
        return {
            "search_id": search_id,
            "candidate_count": len(candidates),
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
        }

    @mcp.tool()
    async def get_album_candidate(candidate_id: str) -> dict[str, Any]:
        """Return a cached album-folder candidate and its complete remote file list."""
        candidate = store.get(candidate_id)
        if not candidate:
            raise ValueError(f"Unknown or expired candidate: {candidate_id}")
        return candidate.model_dump(mode="json")

    @mcp.tool()
    async def queue_album_folder(
        candidate_id: str,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        destination: str | None = None,
        external_id: str = "",
    ) -> dict[str, Any]:
        """
        Queue every supported file in a selected album folder as one slskd batch.

        rights_basis must be one of: owned-copy, licensed, public-domain,
        artist-permission, other-documented-permission.
        """
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        candidate = store.get(candidate_id)
        if not candidate:
            raise ValueError(f"Unknown or expired candidate: {candidate_id}")

        if destination:
            requested_parts = PurePosixPath(destination.replace("\\", "/")).parts
            safe_destination = safe_relative_destination(*requested_parts)
        else:
            safe_destination = safe_relative_destination(candidate.artist, candidate.album)

        result = await client.queue_album_candidate(
            candidate,
            destination=safe_destination,
            external_id=external_id or stable_id("manual-album", candidate_id),
        )
        batch_id = client.batch_id(result)
        local_path = str((settings.downloads_dir / PurePosixPath(safe_destination)).resolve())
        return {
            "rights": {"basis": rights.basis, "reference": rights.reference},
            "candidate": candidate.model_dump(mode="json"),
            "destination": safe_destination,
            "local_path": local_path,
            "batch_id": batch_id,
            "slskd": result,
        }

    @mcp.tool()
    async def list_downloads() -> Any:
        """List current slskd downloads."""
        return await client.list_downloads()

    @mcp.tool()
    async def get_download_batch(batch_id: str) -> Any:
        """Return current status for one slskd download batch."""
        return await client.get_download_batch(batch_id)

    @mcp.tool()
    async def browse_user(username: str) -> Any:
        """Browse the files shared by one Soulseek user."""
        return await client.browse_user(username)

    return mcp


def main() -> None:
    settings = get_soulseek_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    LOGGER.info("Starting Soulseek MCP on %s:%s", settings.mcp_host, settings.mcp_port)
    create_server(settings).run(transport="streamable-http")


if __name__ == "__main__":
    main()
