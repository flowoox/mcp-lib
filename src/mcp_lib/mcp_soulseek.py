from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import get_settings
from .pipeline import MusicPipeline
from .state import StateStore


def create_server() -> FastMCP:
    settings = get_settings()
    state = StateStore(settings.state_db)
    pipeline = MusicPipeline(settings, state)
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
        return await pipeline.slskd.health()

    @mcp.tool()
    async def search_album(
        artist: str,
        album: str,
        max_candidates: int = 10,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Search for complete album folders, including CD1/Disc 2 subfolders."""
        search_id, candidates, _raw = await pipeline.slskd.search_album(
            artist=artist,
            album=album,
            timeout_seconds=timeout_seconds,
            max_candidates=max_candidates,
        )
        for candidate in candidates:
            state.save_candidate(candidate)
        return {
            "search_id": search_id,
            "candidate_count": len(candidates),
            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
        }

    @mcp.tool()
    async def get_album_candidate(candidate_id: str) -> dict[str, Any]:
        """Return a cached album-folder candidate, including the complete remote file list."""
        candidate = state.get_candidate(candidate_id)
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
    ) -> dict[str, Any]:
        """
        Queue every supported file in a selected album folder as one slskd batch.

        rights_basis must be one of: owned-copy, licensed, public-domain,
        artist-permission, other-documented-permission.
        """
        return await pipeline.queue_candidate(
            candidate_id,
            rights_confirmed=rights_confirmed,
            rights_basis=rights_basis,
            rights_reference=rights_reference,
            destination=destination,
        )

    @mcp.tool()
    async def list_downloads() -> Any:
        """List current slskd downloads."""
        return await pipeline.slskd.list_downloads()

    @mcp.tool()
    async def get_download_batch(batch_id: str) -> Any:
        """Return current status for one slskd download batch."""
        return await pipeline.slskd.get_download_batch(batch_id)

    @mcp.tool()
    async def browse_user(username: str) -> Any:
        """Browse the files shared by one Soulseek user."""
        return await pipeline.slskd.browse_user(username)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
