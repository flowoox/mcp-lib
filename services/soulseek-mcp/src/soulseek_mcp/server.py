from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.rights import validate_rights

from .client import SlskdClient, classify_batch
from .config import RuntimeConfig, RuntimeConfigStore, get_settings
from .repository import CandidateRepository


def create_server() -> FastMCP:
    settings = get_settings()
    configs = RuntimeConfigStore(settings)
    candidates = CandidateRepository(settings.soulseek_candidate_file)
    mcp = FastMCP(
        "Soulseek Album MCP",
        instructions="Search complete slskd album folders and queue a selected folder as one download batch.",
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
    )

    def client() -> SlskdClient:
        return SlskdClient(configs.get())

    @mcp.tool()
    async def configure_slskd(base_url: str, api_key: str = "", search_timeout: int = 20, result_limit: int = 300, minimum_tracks: int = 4, preferred_formats: str = "flac,wav,alac,aiff,ape,wv,mp3,m4a,ogg,opus") -> dict[str, Any]:
        """Persist slskd connector settings. The API key is never returned."""
        current = configs.get()
        config = RuntimeConfig(
            base_url=base_url or current.base_url,
            api_key=api_key or current.api_key,
            search_timeout=search_timeout,
            result_limit=result_limit,
            minimum_tracks=minimum_tracks,
            preferred_formats=preferred_formats,
        )
        configs.save(config)
        result = config.model_dump(mode="json")
        result["api_key"] = "***" if config.api_key else ""
        result["ok"] = True
        return result

    @mcp.tool()
    async def get_configuration() -> dict[str, Any]:
        """Return the effective connector configuration with the secret masked."""
        result = configs.get().model_dump(mode="json")
        result["api_key"] = "***" if result.get("api_key") else ""
        return result

    @mcp.tool()
    async def health() -> dict[str, Any]:
        """Check the configured slskd API."""
        return await client().health()

    @mcp.tool()
    async def search_album(artist: str, album: str, max_candidates: int = 10, timeout_seconds: int | None = None) -> dict[str, Any]:
        """Search and rank complete album folders, including multi-disc subfolders."""
        search_id, found, _ = await client().search_album(artist=artist, album=album, timeout_seconds=timeout_seconds, max_candidates=max_candidates)
        candidates.save_many(found)
        return {"search_id": search_id, "candidate_count": len(found), "candidates": [item.model_dump(mode="json") for item in found]}

    @mcp.tool()
    async def get_album_candidate(candidate_id: str) -> dict[str, Any]:
        """Return a cached candidate with its complete remote file list."""
        candidate = candidates.get(candidate_id)
        if not candidate:
            raise ValueError(f"Unknown or expired candidate: {candidate_id}")
        return candidate.model_dump(mode="json")

    @mcp.tool()
    async def queue_album_folder(candidate_id: str, rights_confirmed: bool, rights_basis: str, rights_reference: str = "", destination: str | None = None, external_id: str | None = None) -> dict[str, Any]:
        """Queue every safe file of an authorized album candidate as one slskd batch."""
        rights = validate_rights(confirmed=rights_confirmed, basis=rights_basis, reference=rights_reference)
        candidate = candidates.get(candidate_id)
        if not candidate:
            raise ValueError(f"Unknown or expired candidate: {candidate_id}")
        result = await client().queue_candidate(candidate, destination=destination, external_id=external_id)
        result["candidate_id"] = candidate_id
        result["rights"] = rights.as_dict()
        return result

    @mcp.tool()
    async def list_downloads() -> Any:
        """List current downloads from slskd."""
        return await client().list_downloads()

    @mcp.tool()
    async def get_download_batch(batch_id: str) -> dict[str, Any]:
        """Return raw and normalized status for one slskd batch."""
        payload = await client().get_batch(batch_id)
        return {"batch_id": batch_id, "state": classify_batch(payload), "batch": payload}

    @mcp.tool()
    async def wait_for_download(batch_id: str, timeout_seconds: int = 3600, poll_seconds: int = 10) -> dict[str, Any]:
        """Poll a batch until it completes, fails, or reaches the timeout."""
        return await client().wait_for_batch(batch_id, timeout_seconds=timeout_seconds, poll_seconds=poll_seconds)

    @mcp.tool()
    async def browse_user(username: str) -> Any:
        """Browse one Soulseek user's shares."""
        return await client().browse_user(username)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
