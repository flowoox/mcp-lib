from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.paths import resolve_contained_path
from mcp_common.store import AtomicJsonStore
from mcp_common.url_security import origin_for_url

from .client import TraxxClient
from .config import ActorRegistry, RuntimeConfig, RuntimeConfigStore, get_settings
from .contract import capabilities
from .metadata import inspect_audio_file


def create_server() -> FastMCP:
    settings = get_settings()
    configs = RuntimeConfigStore(settings)
    import_ledger = AtomicJsonStore(settings.traxx_import_ledger_file, default={})
    actors = ActorRegistry(settings.traxx_actors_file)
    import_locks: dict[str, asyncio.Lock] = {}
    security = build_mcp_server_security(settings, service_hosts=("mcp-traxx",))
    mcp = FastMCP(
        "Traxx BeMusic MCP",
        instructions=(
            "Use the native Traxx/BeMusic API and TUS upload flow. "
            "Local paths are restricted to DOWNLOADS_DIR."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the stable MCP contract and supported features."""
        return capabilities()

    def _allowed_traxx_origins() -> set[str]:
        allowed: set[str] = set()
        if settings.traxx_url.strip():
            allowed.add(origin_for_url(settings.traxx_url))
        for value in settings.traxx_allowed_origins.split(","):
            value = value.strip()
            if value:
                allowed.add(origin_for_url(value))
        return allowed

    def _validate_target_origin(current: RuntimeConfig, target_url: str) -> None:
        target_origin = origin_for_url(target_url)
        current_origin = origin_for_url(current.base_url) if current.base_url else ""
        if target_origin == current_origin:
            return
        allowed = _allowed_traxx_origins()
        if target_origin in allowed:
            return
        # First-time bootstrap is permitted only while no credential exists.
        # Once an origin or any token-bearing state exists, moving the client
        # requires an operator-approved TRAXX_ALLOWED_ORIGINS entry.
        if not current_origin and not current.token and not current.extra_headers and not actors.has_tokens():
            return
        raise ValueError(
            "Changing the Traxx origin is blocked because it could forward existing "
            "service, proxy, or actor credentials. Add the exact destination origin "
            "to TRAXX_ALLOWED_ORIGINS at deployment time before migrating it."
        )

    def client(actor_id: str = "") -> TraxxClient:
        """Build a client, optionally acting as a registered Traxx user.

        An empty actor_id keeps the service-account token; otherwise the
        actor's bearer token is resolved from the registry and an unknown
        actor_id raises before any request is made.
        """
        config = configs.get()
        if not config.verify_tls and not settings.traxx_allow_insecure_tls:
            raise ValueError(
                "Traxx TLS verification is disabled in persisted configuration, but "
                "TRAXX_ALLOW_INSECURE_TLS is not enabled for this deployment."
            )
        actor_token = actors.token_for(actor_id) if actor_id.strip() else ""
        return TraxxClient(
            config,
            downloads_dir=settings.downloads_dir,
            import_ledger=import_ledger,
            actor_token=actor_token,
        )

    @mcp.tool()
    async def configure_traxx(
        base_url: str,
        token: str = "",
        verify_tls: bool = True,
        tus_endpoint: str = "/api/v1/tus/",
        upload_chunk_size: int = 8_388_608,
        file_url_template: str = "",
        timeout_seconds: int = 90,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Persist Traxx connector settings. The bearer token is never returned.

        extra_headers is sent with every request so a proxy or WAF in front of
        the instance can admit this client without exposing the API publicly.
        """
        current = configs.get()
        target_url = base_url or current.base_url
        if not target_url:
            raise ValueError("Traxx base_url must be configured")
        _validate_target_origin(current, target_url)
        if not verify_tls and not settings.traxx_allow_insecure_tls:
            raise ValueError(
                "verify_tls=false is restricted to an explicit development deployment; "
                "set TRAXX_ALLOW_INSECURE_TLS=true only for that isolated environment."
            )
        config = RuntimeConfig(
            base_url=target_url,
            token=token or current.token,
            extra_headers=(
                current.extra_headers if extra_headers is None else extra_headers
            ),
            verify_tls=verify_tls,
            tus_endpoint=tus_endpoint,
            upload_chunk_size=upload_chunk_size,
            file_url_template=file_url_template,
            timeout_seconds=timeout_seconds,
        )
        configs.save(config)
        result = config.model_dump(mode="json")
        result["token"] = "***" if config.token else ""
        # Header names identify the proxy rule; their values are secrets.
        result["extra_headers"] = {key: "***" for key in config.extra_headers}
        result["ok"] = True
        return result

    @mcp.tool()
    async def get_configuration() -> dict[str, Any]:
        """Return effective Traxx settings with the token masked."""
        result = configs.get().model_dump(mode="json")
        result["token"] = "***" if result.get("token") else ""
        result["extra_headers"] = {key: "***" for key in result.get("extra_headers") or {}}
        return result

    @mcp.tool()
    async def configure_traxx_actor(actor_id: str, token: str) -> dict[str, Any]:
        """Register or replace the bearer token for an orchestrator-chosen actor.

        Requests carrying this actor_id run as that Traxx user. The token is
        stored server-side and never returned by any tool output.
        """
        stored_id = actors.set(actor_id, token)
        return {"ok": True, "actor_id": stored_id, "token": "***"}

    @mcp.tool()
    async def remove_traxx_actor(actor_id: str) -> dict[str, Any]:
        """Delete a registered actor token. Unknown ids report removed=False."""
        removed = actors.remove(actor_id)
        return {"ok": True, "actor_id": actor_id.strip(), "removed": removed}

    @mcp.tool()
    async def list_traxx_actors() -> dict[str, Any]:
        """List registered actor ids. Tokens are never included."""
        ids = actors.list_ids()
        return {"actors": ids, "count": len(ids)}

    @mcp.tool()
    async def health() -> dict[str, Any]:
        return await client().health()

    @mcp.tool()
    async def list_tracks(
        page: int = 1, per_page: int = 20, query: str = ""
    ) -> Any:
        return await client().list_resource(
            "tracks", page=page, per_page=per_page, query=query
        )

    @mcp.tool()
    async def list_albums(
        page: int = 1, per_page: int = 20, query: str = ""
    ) -> Any:
        return await client().list_resource(
            "albums", page=page, per_page=per_page, query=query
        )

    @mcp.tool()
    async def list_artists(
        page: int = 1, per_page: int = 20, query: str = ""
    ) -> Any:
        return await client().list_resource(
            "artists", page=page, per_page=per_page, query=query
        )

    @mcp.tool()
    async def diagnose_connection() -> dict[str, Any]:
        """Report effective URLs and responses, for comparison against curl."""
        return await client().diagnose_connection()

    @mcp.tool()
    async def list_members(page: int = 1, per_page: int = 50) -> dict[str, Any]:
        """List the instance's accounts with their email addresses.

        The address is what ties a listener here to the same person on
        Spotify, so their taste can be read as one instead of two halves.
        """
        return {"members": await client().list_members(page=page, per_page=per_page)}

    @mcp.tool()
    async def member_taste(
        user_id: str = "", pages: int = 2, per_page: int = 50
    ) -> dict[str, Any]:
        """Rank artists by what one account has marked as theirs.

        An empty user_id reads the connected account. A liked artist weighs
        more than a liked album, which weighs more than a single liked track.
        """
        return await client().member_taste(user_id, pages=pages, per_page=per_page)

    @mcp.tool()
    async def list_liked(
        resource: str = "artists",
        page: int = 1,
        per_page: int = 50,
        actor_id: str = "",
    ) -> Any:
        """List liked artists, albums or tracks of the acting account."""
        return await client(actor_id).list_liked(resource, page=page, per_page=per_page)

    @mcp.tool()
    async def search_library(query: str, resource: str = "artists", limit: int = 20) -> Any:
        """Find artists, albums or tracks by name through the search route."""
        return await client().search_resource(resource, query, limit=limit)

    @mcp.tool()
    async def inspect_local_track(path: str) -> dict[str, Any]:
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return {
            "path": str(resolved),
            "metadata": inspect_audio_file(resolved).as_dict(),
        }

    @mcp.tool()
    async def diagnose_upload(path: str) -> dict[str, Any]:
        """Report TUS/FileEntry/metadata details without creating a track."""
        resolved = resolve_contained_path(settings.downloads_dir, path)
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        return await client().diagnose_upload(resolved)

    @mcp.tool()
    async def import_album_folder(
        path: str,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        dry_run: bool = True,
        artist: str = "",
        album: str = "",
        release_date: str = "",
        cover_url: str = "",
        genres: list[str] | None = None,
        track_hints: list[dict[str, Any]] | None = None,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        """Normalize local tags and import a complete album into Traxx.

        Album metadata supplied by the orchestrator overrides unreliable
        Soulseek tags. Track hints are matched by disc/track number and the
        selected cover is embedded in the local source files before upload.
        """
        lock_key = idempotency_key.strip() or f"legacy:{path}"
        lock = import_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            return await client().import_album_folder(
                path,
                dry_run=dry_run,
                rights_confirmed=rights_confirmed,
                rights_basis=rights_basis,
                rights_reference=rights_reference,
                artist=artist,
                album=album,
                release_date=release_date,
                cover_url=cover_url,
                genres=genres,
                track_hints=track_hints,
                idempotency_key=idempotency_key,
            )

    @mcp.tool()
    async def import_external_metadata(
        model_type: str,
        provider: str,
        external_id: str,
        import_similar_artists: bool = False,
        import_albums: bool = False,
        import_lyrics: bool = False,
    ) -> Any:
        return await client().import_metadata(
            model_type=model_type,
            provider=provider,
            external_id=external_id,
            import_similar_artists=import_similar_artists,
            import_albums=import_albums,
            import_lyrics=import_lyrics,
        )

    @mcp.tool()
    async def create_playlist(
        name: str, description: str = "", public: bool = False, actor_id: str = ""
    ) -> Any:
        return await client(actor_id).create_playlist(
            name=name, description=description, public=public
        )

    @mcp.tool()
    async def add_playlist_tracks(
        playlist_id: int, track_ids: list[int], actor_id: str = ""
    ) -> Any:
        return await client(actor_id).add_playlist_tracks(
            playlist_id=playlist_id, track_ids=track_ids
        )

    @mcp.tool()
    async def remove_playlist_tracks(
        playlist_id: int, track_ids: list[int], actor_id: str = ""
    ) -> Any:
        return await client(actor_id).remove_playlist_tracks(
            playlist_id=playlist_id, track_ids=track_ids
        )

    @mcp.tool()
    async def replace_playlist_tracks(
        playlist_id: int, track_ids: list[int], actor_id: str = ""
    ) -> Any:
        """Make the playlist contain exactly track_ids (read, remove, add)."""
        return await client(actor_id).replace_playlist_tracks(
            playlist_id=playlist_id, track_ids=track_ids
        )

    @mcp.tool()
    async def list_playlists(
        page: int = 1, per_page: int = 20, actor_id: str = ""
    ) -> Any:
        """List the playlists of the acting account."""
        return await client(actor_id).list_playlists(page=page, per_page=per_page)

    @mcp.tool()
    async def get_playlist(playlist_id: int, actor_id: str = "") -> Any:
        """Return playlist details including its tracks."""
        return await client(actor_id).get_playlist(playlist_id)

    @mcp.tool()
    async def update_playlist(
        playlist_id: int,
        name: str = "",
        description: str = "",
        public: bool | None = None,
        actor_id: str = "",
    ) -> Any:
        """Partially update a playlist; only supplied fields are sent."""
        return await client(actor_id).update_playlist(
            playlist_id=playlist_id,
            name=name,
            description=description,
            public=public,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
