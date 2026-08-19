from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.rights import validate_rights

from .client import SlskdClient, classify_batch
from .config import RuntimeConfig, RuntimeConfigStore, get_settings
from .contract import capabilities
from .repository import BatchRepository, CandidateRepository
from .slskd_config import SlskdConfigurationWriter


def create_server() -> FastMCP:
    settings = get_settings()
    configs = RuntimeConfigStore(settings)
    candidates = CandidateRepository(settings.soulseek_candidate_file)
    batches = BatchRepository(settings.soulseek_batch_file)
    slskd_config = SlskdConfigurationWriter(settings.slskd_config_path)
    queue_locks: dict[str, asyncio.Lock] = {}
    security = build_mcp_server_security(settings, service_hosts=("mcp-soulseek",))
    mcp = FastMCP(
        "Soulseek Album MCP",
        instructions=(
            "Configure slskd and search complete album folders. Queue a selected "
            "folder as one download batch."
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

    def client() -> SlskdClient:
        return SlskdClient(
            configs.get(),
            batches=batches,
            downloads_dir=settings.downloads_dir,
        )

    @mcp.tool()
    async def configure_slskd(
        base_url: str,
        api_key: str = "",
        search_timeout: int = 20,
        result_limit: int = 300,
        minimum_tracks: int = 4,
        preferred_formats: str = "flac,wav,alac,aiff,aif,ape,wv",
        lossless_only: bool = True,
        minimum_lossy_bitrate_kbps: int = 320,
        soulseek_username: str = "",
        soulseek_password: str = "",
        web_username: str = "",
        web_password: str = "",
        listen_port: int = 50300,
    ) -> dict[str, Any]:
        """Persist API, search, quality and optional account settings.

        By default only lossless formats are accepted. When lossless_only is
        disabled, every lossy file must report at least
        minimum_lossy_bitrate_kbps. Secrets are input-only and never returned.
        """
        current = configs.get()
        config = RuntimeConfig(
            base_url=base_url or current.base_url,
            api_key=api_key or current.api_key,
            search_timeout=search_timeout,
            result_limit=result_limit,
            minimum_tracks=minimum_tracks,
            preferred_formats=preferred_formats,
            lossless_only=lossless_only,
            minimum_lossy_bitrate_kbps=minimum_lossy_bitrate_kbps,
        )
        configs.save(config)

        account_requested = any(
            (soulseek_username, soulseek_password, web_username, web_password)
        )
        if account_requested:
            slskd_config.write(
                soulseek_username=soulseek_username,
                soulseek_password=soulseek_password,
                api_key=config.api_key,
                web_username=web_username,
                web_password=web_password,
                listen_port=listen_port,
            )

        result = config.model_dump(mode="json")
        result["api_key"] = "***" if config.api_key else ""
        result["account_configured"] = account_requested
        if account_requested:
            # slskd only reads the account at startup, so a freshly written
            # file leaves it disconnected until something asks it to log in.
            try:
                result["connection"] = await SlskdClient(config).connect_soulseek()
            except Exception as exc:
                result["connection"] = {"logged_in": False, "error": str(exc)}
        result["ok"] = True
        return result

    @mcp.tool()
    async def connect_soulseek() -> dict[str, Any]:
        """Log slskd into the Soulseek network and report the resulting state."""
        return await client().connect_soulseek()

    @mcp.tool()
    async def server_status() -> dict[str, Any]:
        """Report the Soulseek connection state without changing it."""
        return await client().server_status()

    @mcp.tool()
    async def get_configuration() -> dict[str, Any]:
        """Return effective connector settings with all secrets masked."""
        result = configs.get().model_dump(mode="json")
        result["api_key"] = "***" if result.get("api_key") else ""
        result["slskd_yaml_present"] = settings.slskd_config_path.is_file()
        return result

    @mcp.tool()
    async def health() -> dict[str, Any]:
        """Check the configured slskd API."""
        return await client().health()

    @mcp.tool()
    async def search_album(
        artist: str,
        album: str,
        expected_track_count: int | None = None,
        max_candidates: int = 10,
        timeout_seconds: int | None = None,
        lossless_only: bool | None = None,
        minimum_lossy_bitrate_kbps: int | None = None,
        search_text: str | None = None,
    ) -> dict[str, Any]:
        """Search and rank complete album folders, including multi-disc subfolders.

        Folders that were found but did not pass are reported with the quality
        they actually offer, so an empty result can be told apart from a strict
        gate. The quality arguments override the stored settings for this
        search only. ``search_text`` replaces the default ``artist album``
        query: peers require every term to occur in the file path, so a niche
        release often answers only to a shorter one.
        """
        search_id, found, stats = await client().search_album(
            artist=artist,
            album=album,
            expected_track_count=expected_track_count,
            timeout_seconds=timeout_seconds,
            max_candidates=max_candidates,
            lossless_only=lossless_only,
            minimum_lossy_bitrate_kbps=minimum_lossy_bitrate_kbps,
            search_text=search_text,
        )
        candidates.save_many(found)
        return {
            "search_id": search_id,
            "candidate_count": len(found),
            "candidates": [item.model_dump(mode="json") for item in found],
            "responses": stats.get("responses", 0),
            "rejected": stats.get("rejected", []),
            "lossless_only": stats.get("lossless_only"),
            "minimum_lossy_bitrate_kbps": stats.get("minimum_lossy_bitrate_kbps"),
            "search_text": stats.get("search_text"),
        }

    @mcp.tool()
    async def get_album_candidate(candidate_id: str) -> dict[str, Any]:
        """Return a cached candidate with its complete remote file list."""
        candidate = candidates.get(candidate_id)
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
        external_id: str | None = None,
    ) -> dict[str, Any]:
        """Queue every safe file of an authorized album candidate as one batch."""
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        lock_key = f"{external_id or candidate_id}:{candidate_id}"
        lock = queue_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            candidate = candidates.get(candidate_id)
            if not candidate:
                result = await client().get_existing_operation_batch(
                    candidate_id=candidate_id,
                    external_id=external_id,
                    destination=destination,
                )
                if result is None:
                    raise ValueError(f"Unknown or expired candidate: {candidate_id}")
            else:
                result = await client().queue_candidate(
                    candidate,
                    destination=destination,
                    external_id=external_id,
                )
        result["candidate_id"] = candidate_id
        result["rights"] = rights.as_dict()
        return result

    @mcp.tool()
    async def cancel_download_batch(batch_id: str, remove: bool = False) -> dict[str, Any]:
        """Stop every unfinished transfer of one album.

        Files that already arrived are left alone unless ``remove`` is set —
        cancelling those would throw away a download that succeeded.
        """
        return await client().cancel_batch(batch_id, remove=remove)

    @mcp.tool()
    async def list_downloads() -> Any:
        """List current downloads from slskd."""
        return await client().list_downloads()

    @mcp.tool()
    async def get_download_batch(batch_id: str) -> dict[str, Any]:
        """Return normalized status and the transfers one album consists of.

        Once every file has arrived, they are moved into the folder that was
        requested when the album was queued, and ``collected`` says what moved.
        """
        payload = await client().get_batch(batch_id)
        return {
            "batch_id": batch_id,
            "state": payload.get("state") or classify_batch(payload),
            "batch": payload,
        }

    @mcp.tool()
    async def wait_for_download(
        batch_id: str,
        timeout_seconds: int = 3600,
        poll_seconds: int = 10,
    ) -> dict[str, Any]:
        """Poll a batch until it completes, fails, or reaches the timeout."""
        return await client().wait_for_batch(
            batch_id,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )

    @mcp.tool()
    async def browse_user(username: str) -> Any:
        """Browse one Soulseek user's shares."""
        return await client().browse_user(username)

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
