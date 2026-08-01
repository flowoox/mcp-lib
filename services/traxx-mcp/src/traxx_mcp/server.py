from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.paths import resolve_contained_path

from .client import TraxxClient
from .config import RuntimeConfig, RuntimeConfigStore, get_settings
from .metadata import inspect_audio_file


def create_server() -> FastMCP:
    settings = get_settings()
    configs = RuntimeConfigStore(settings)
    mcp = FastMCP(
        "Traxx BeMusic MCP",
        instructions="Use the native Traxx/BeMusic API and TUS upload flow. Local paths are restricted to DOWNLOADS_DIR.",
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
    )

    def client() -> TraxxClient:
        return TraxxClient(configs.get(), downloads_dir=settings.downloads_dir)

    @mcp.tool()
    async def configure_traxx(base_url: str, token: str = "", verify_tls: bool = True, tus_endpoint: str = "/api/v1/tus/", upload_chunk_size: int = 8388608, file_url_template: str = "", timeout_seconds: int = 90) -> dict[str, Any]:
        """Persist Traxx connector settings. The bearer token is never returned."""
        current = configs.get()
        config = RuntimeConfig(base_url=base_url or current.base_url, token=token or current.token, verify_tls=verify_tls, tus_endpoint=tus_endpoint, upload_chunk_size=upload_chunk_size, file_url_template=file_url_template, timeout_seconds=timeout_seconds)
        configs.save(config)
        result = config.model_dump(mode="json")
        result["token"] = "***" if config.token else ""
        result["ok"] = True
        return result

    @mcp.tool()
    async def get_configuration() -> dict[str, Any]:
        """Return effective Traxx settings with the token masked."""
        result = configs.get().model_dump(mode="json")
        result["token"] = "***" if result.get("token") else ""
        return result

    @mcp.tool()
    async def health() -> dict[str, Any]:
        return await client().health()

    @mcp.tool()
    async def list_tracks(page: int = 1, per_page: int = 20, query: str = "") -> Any:
        return await client().list_resource("tracks", page=page, per_page=per_page, query=query)

    @mcp.tool()
    async def list_albums(page: int = 1, per_page: int = 20, query: str = "") -> Any:
        return await client().list_resource("albums", page=page, per_page=per_page, query=query)

    @mcp.tool()
    async def list_artists(page: int = 1, per_page: int = 20, query: str = "") -> Any:
        return await client().list_resource("artists", page=page, per_page=per_page, query=query)

    @mcp.tool()
    async def inspect_local_track(path: str) -> dict[str, Any]:
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return {"path": str(resolved), "metadata": inspect_audio_file(resolved).as_dict()}

    @mcp.tool()
    async def diagnose_upload(path: str) -> dict[str, Any]:
        """Upload one file and report TUS/FileEntry/metadata details without creating a track."""
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return await client().diagnose_upload(resolved)

    @mcp.tool()
    async def import_album_folder(path: str, rights_confirmed: bool, rights_basis: str, rights_reference: str = "", dry_run: bool = True) -> dict[str, Any]:
        return await client().import_album_folder(path, dry_run=dry_run, rights_confirmed=rights_confirmed, rights_basis=rights_basis, rights_reference=rights_reference)

    @mcp.tool()
    async def import_external_metadata(model_type: str, provider: str, external_id: str, import_similar_artists: bool = False, import_albums: bool = False, import_lyrics: bool = False) -> Any:
        return await client().import_metadata(model_type=model_type, provider=provider, external_id=external_id, import_similar_artists=import_similar_artists, import_albums=import_albums, import_lyrics=import_lyrics)

    @mcp.tool()
    async def create_playlist(name: str, description: str = "", public: bool = False) -> Any:
        return await client().create_playlist(name=name, description=description, public=public)

    @mcp.tool()
    async def add_playlist_tracks(playlist_id: int, track_ids: list[int]) -> Any:
        return await client().add_playlist_tracks(playlist_id=playlist_id, track_ids=track_ids)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
