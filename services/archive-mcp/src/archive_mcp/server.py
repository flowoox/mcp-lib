from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.rights import validate_rights

from .config import RuntimeConfig, RuntimeConfigStore, get_settings
from .contract import capabilities
from .repository import BatchRepository, CandidateRepository
from .secure_client import SecureArchiveClient


def create_server() -> FastMCP:
    settings = get_settings()
    configs = RuntimeConfigStore(settings)
    candidates = CandidateRepository(settings.archive_candidate_file)
    batches = BatchRepository(settings.archive_batch_file)
    queue_locks: dict[str, asyncio.Lock] = {}
    # Transfers run past the tool call that started them, so the tasks are
    # owned by the server rather than by any one request.
    transfers: dict[str, asyncio.Task[None]] = {}
    security = build_mcp_server_security(settings, service_hosts=("mcp-archive",))
    mcp = FastMCP(
        "Internet Archive Album MCP",
        instructions=(
            "Search openly licensed albums on archive.org and fetch one item "
            "into the shared downloads volume. Only items whose licence can be "
            "read from their metadata are offered."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    def client() -> SecureArchiveClient:
        return SecureArchiveClient(
            configs.get(),
            batches=batches,
            downloads_dir=settings.downloads_dir,
            tasks=transfers,
        )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        """Return the stable MCP contract and supported features."""
        return capabilities()

    @mcp.tool()
    async def configure_archive(
        base_url: str = "",
        user_agent: str = "",
        search_timeout: int = 30,
        result_limit: int = 40,
        metadata_probe_limit: int = 12,
        minimum_tracks: int = 1,
        preferred_formats: str = "flac,wav,aiff,aif,mp3,ogg,m4a",
        lossless_only: bool = False,
        minimum_lossy_bitrate_kbps: int = 128,
        max_parallel_downloads: int = 3,
        download_timeout_seconds: int = 900,
    ) -> dict[str, Any]:
        """Persist Archive search and quality settings.

        ``base_url`` is retained for backwards-compatible clients but is now a
        fail-closed trust-boundary parameter: only the bare
        ``https://archive.org`` origin is accepted. Download redirects are
        separately revalidated hop-by-hop before any request is sent.
        """
        current = configs.get()
        config = RuntimeConfig(
            base_url=base_url or current.base_url,
            user_agent=user_agent or current.user_agent,
            search_timeout=search_timeout,
            result_limit=result_limit,
            metadata_probe_limit=metadata_probe_limit,
            minimum_tracks=minimum_tracks,
            preferred_formats=preferred_formats,
            lossless_only=lossless_only,
            minimum_lossy_bitrate_kbps=minimum_lossy_bitrate_kbps,
            max_parallel_downloads=max_parallel_downloads,
            download_timeout_seconds=download_timeout_seconds,
        )
        configs.save(config)
        result = config.model_dump(mode="json")
        result["ok"] = True
        return result

    @mcp.tool()
    async def get_configuration() -> dict[str, Any]:
        """Return the effective connector settings."""
        return configs.get().model_dump(mode="json")

    @mcp.tool()
    async def health() -> dict[str, Any]:
        """Check that archive.org answers and its audio index is populated."""
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
        """Search openly licensed albums and rank the items that may be copied.

        Items are rejected when their licence cannot be read from the
        metadata; the reason travels in ``rejected`` so an empty result can be
        told apart from "nothing matched". ``search_text`` replaces the
        generated query for callers that want to widen it themselves.
        """
        search_id, found, stats = await client().search_album(
            artist=artist,
            album=album,
            expected_track_count=expected_track_count,
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
            "items_probed": stats.get("items_probed", 0),
            "rejected": stats.get("rejected", []),
            "lossless_only": stats.get("lossless_only"),
            "minimum_lossy_bitrate_kbps": stats.get("minimum_lossy_bitrate_kbps"),
            "search_text": stats.get("search_text"),
        }

    @mcp.tool()
    async def get_album_candidate(candidate_id: str) -> dict[str, Any]:
        """Return a cached candidate with its complete file list and licence."""
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
        """Fetch every file of an authorized item into the shared volume.

        The caller's rights assertion is validated exactly as in the Soulseek
        connector. On top of that the item's own licence has to allow
        redistribution, and when the caller supplies no reference the licence
        URL from the item is used as one.
        """
        candidate = candidates.get(candidate_id)
        # The item states a licence; using it as the reference means an audit
        # can see *which* licence the copy was made under, not just that
        # somebody ticked a box.
        reference = rights_reference or (candidate.license_url if candidate else "")
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=reference,
        )
        lock_key = f"{external_id or candidate_id}:{candidate_id}"
        lock = queue_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
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
    async def list_downloads() -> list[dict[str, Any]]:
        """List every item this connector has been asked to fetch."""
        return client().list_downloads()

    @mcp.tool()
    async def get_download_batch(batch_id: str) -> dict[str, Any]:
        """Return normalized status and the files one item consists of."""
        payload = client().get_batch(batch_id)
        return {
            "batch_id": batch_id,
            "state": payload.get("state") or "unknown",
            "batch": payload,
        }

    @mcp.tool()
    async def wait_for_download(
        batch_id: str,
        timeout_seconds: int = 3600,
        poll_seconds: int = 5,
    ) -> dict[str, Any]:
        """Poll one item until it completes, fails, or reaches the timeout."""
        return await client().wait_for_batch(
            batch_id,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
