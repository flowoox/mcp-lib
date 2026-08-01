from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import TraxxSettings, get_traxx_settings
from .rights import validate_rights
from .traxx import TraxxClient, inspect_audio_file
from .utils import resolve_contained_path

LOGGER = logging.getLogger(__name__)


def create_server(settings: TraxxSettings | None = None) -> FastMCP:
    settings = settings or get_traxx_settings()
    client = TraxxClient(
        base_url=settings.traxx_url,
        token=settings.traxx_token,
        tus_endpoint=settings.traxx_tus_endpoint,
        verify_tls=settings.traxx_verify_tls,
        upload_chunk_size=settings.traxx_upload_chunk_size,
        file_url_template=settings.traxx_file_url_template,
        downloads_dir=settings.downloads_dir,
    )
    mcp = FastMCP(
        "Traxx BeMusic MCP",
        instructions=(
            "Wraps the native Traxx/BeMusic v1 API and TUS upload endpoint. "
            "Local paths are restricted to DOWNLOADS_DIR. Upload/import side effects "
            "require an explicit rights assertion."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
    )

    @mcp.tool()
    async def health() -> dict[str, Any]:
        """Check whether Traxx responds on its tracks API."""
        return await client.health()

    @mcp.tool()
    async def list_tracks(page: int = 1, per_page: int = 20, query: str = "") -> Any:
        """List or search tracks through the native Traxx API."""
        return await client.list_tracks(page=page, per_page=per_page, query=query)

    @mcp.tool()
    async def list_albums(page: int = 1, per_page: int = 20, query: str = "") -> Any:
        """List or search albums through the native Traxx API."""
        return await client.list_albums(page=page, per_page=per_page, query=query)

    @mcp.tool()
    async def inspect_local_track(path: str) -> dict[str, Any]:
        """Read tags and duration without uploading. Path must be inside DOWNLOADS_DIR."""
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return {"path": str(resolved), "metadata": asdict(inspect_audio_file(resolved))}

    @mcp.tool()
    async def upload_track_file(
        path: str,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
    ) -> dict[str, Any]:
        """Upload one authorized local audio file to Traxx through its TUS endpoint."""
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        result = await client.upload_file(resolved, upload_type="track")
        result["rights"] = {"basis": rights.basis, "reference": rights.reference}
        return result

    @mcp.tool()
    async def import_album_folder(
        path: str,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Inspect or import every audio track below one authorized album folder.

        dry_run defaults to true. A live import uploads with TUS, extracts BeMusic
        metadata, auto-matches artist/album, and creates track records when the
        native upload response can be mapped to a playable src URL.
        """
        return await client.import_album_folder(
            path,
            dry_run=dry_run,
            rights_confirmed=rights_confirmed,
            rights_basis=rights_basis,
            rights_reference=rights_reference,
        )

    @mcp.tool()
    async def import_spotify_metadata(model_type: str, spotify_id: str) -> Any:
        """Ask Traxx to import Spotify metadata for an artist, album, track, or playlist."""
        return await client.import_spotify_metadata(
            model_type=model_type,
            spotify_id=spotify_id,
        )

    return mcp


def main() -> None:
    settings = get_traxx_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    LOGGER.info("Starting Traxx MCP on %s:%s", settings.mcp_host, settings.mcp_port)
    create_server(settings).run(transport="streamable-http")


if __name__ == "__main__":
    main()
