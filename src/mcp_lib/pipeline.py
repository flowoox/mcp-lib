from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .config import Settings
from .models import ConnectorHealth, Recommendation
from .rights import RightsError, validate_automation_rights, validate_rights
from .slskd import SlskdClient
from .spotify import SpotifyClient, TokenCipher
from .state import StateStore
from .traxx import TraxxClient
from .utils import (
    get_case_insensitive,
    safe_relative_destination,
    stable_id,
    walk_dicts,
)

COMPLETE_STATES = {
    "completed",
    "complete",
    "succeeded",
    "success",
    "finished",
}
FAILED_STATES = {
    "cancelled",
    "canceled",
    "errored",
    "error",
    "failed",
    "rejected",
    "timedout",
    "timed_out",
}
ACTIVE_STATES = {
    "queued",
    "requested",
    "initializing",
    "inprogress",
    "in_progress",
    "downloading",
    "transferring",
}


class MusicPipeline:
    def __init__(self, settings: Settings, state: StateStore | None = None):
        self.settings = settings
        self.state = state or StateStore(settings.state_db)
        self.cipher = TokenCipher(settings.app_secret)
        self.slskd = SlskdClient(
            base_url=settings.slskd_url,
            api_key=settings.slskd_api_key,
            search_timeout=settings.slskd_search_timeout,
            result_limit=settings.slskd_result_limit,
            minimum_tracks=settings.slskd_minimum_tracks,
            preferred_formats=settings.preferred_audio_formats,
        )
        self.traxx = TraxxClient(
            base_url=settings.traxx_url,
            token=settings.traxx_token,
            tus_endpoint=settings.traxx_tus_endpoint,
            verify_tls=settings.traxx_verify_tls,
            upload_chunk_size=settings.traxx_upload_chunk_size,
            file_url_template=settings.traxx_file_url_template,
            downloads_dir=settings.downloads_dir,
        )

    async def spotify_for_profile(self, profile_id: str) -> SpotifyClient:
        profile = self.state.get_profile(profile_id)
        if not profile:
            raise KeyError(f"Unknown Spotify profile: {profile_id}")
        token = self.cipher.decrypt(str(profile["encrypted_token"]))
        client = SpotifyClient(client_id=self.settings.spotify_client_id, token=token)
        refreshed_token, changed = await client.ensure_fresh_token()
        if changed:
            self.state.update_profile_token(profile_id, self.cipher.encrypt(refreshed_token))
        return client

    async def discover(
        self,
        *,
        profile_id: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        profile = self.state.get_profile(profile_id) if profile_id else self.state.get_selected_profile()
        if not profile:
            raise RuntimeError("No Spotify profile is connected and selected")
        profile_id = str(profile["id"])
        limit = limit or self.settings.discovery_albums_per_day
        job_id = self.state.start_job("spotify-discovery", {"profile_id": profile_id, "limit": limit})
        try:
            client = await self.spotify_for_profile(profile_id)
            history = self.state.history_keys(profile_id)
            analysis, albums = await client.discover_albums(
                excluded_history_keys=history,
                limit=limit,
            )
            # A refresh can occur during any API call.
            self.state.update_profile_token(profile_id, self.cipher.encrypt(client.token))
            recommendations: list[Recommendation] = []
            for album in albums:
                recommendation = Recommendation(
                    id=stable_id("recommendation", profile_id, album.spotify_id),
                    profile_id=profile_id,
                    spotify_album_id=album.spotify_id,
                    artist=album.primary_artist,
                    album=album.name,
                    release_date=album.release_date,
                    image_url=album.image_url,
                    spotify_url=album.spotify_url,
                    score=album.score,
                    source_reasons=album.source_reasons,
                )
                self.state.upsert_recommendation(recommendation)
                self.state.add_history(profile_id, album.album_key, "recommended")
                recommendations.append(recommendation)
            result = {
                "job_id": job_id,
                "profile": {
                    "id": profile_id,
                    "display_name": profile.get("display_name"),
                    "spotify_user_id": profile.get("spotify_user_id"),
                },
                "analysis": analysis,
                "recommendations": [item.model_dump(mode="json") for item in recommendations],
            }
            self.state.finish_job(job_id, "completed", result)
            return result
        except Exception as exc:
            self.state.finish_job(job_id, "failed", {"error": str(exc)})
            raise

    async def queue_recommendation(
        self,
        recommendation_id: str,
        *,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        minimum_score: float = 35,
    ) -> dict[str, Any]:
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        recommendation = self.state.get_recommendation(recommendation_id)
        if not recommendation:
            raise KeyError(f"Unknown recommendation: {recommendation_id}")
        self.state.update_recommendation(
            recommendation_id,
            status="searching",
            rights_basis=rights.basis,
            rights_reference=rights.reference,
        )
        try:
            search_id, candidates, _raw = await self.slskd.search_album(
                artist=recommendation.artist,
                album=recommendation.album,
            )
            for candidate in candidates:
                self.state.save_candidate(candidate)
            if not candidates:
                self.state.update_recommendation(recommendation_id, status="not_found")
                return {
                    "ok": False,
                    "status": "not_found",
                    "search_id": search_id,
                    "message": "No complete album folder met the configured track and file filters.",
                }
            selected = candidates[0]
            if selected.score < minimum_score:
                self.state.update_recommendation(
                    recommendation_id,
                    status="needs_review",
                    candidate_id=selected.candidate_id,
                )
                return {
                    "ok": False,
                    "status": "needs_review",
                    "search_id": search_id,
                    "candidate": selected.model_dump(mode="json"),
                    "message": f"Best folder scored {selected.score:.1f}, below threshold {minimum_score:.1f}.",
                }

            destination = safe_relative_destination(
                "spotify",
                recommendation.profile_id,
                recommendation.artist,
                recommendation.album,
            )
            result = await self.slskd.queue_album_candidate(
                selected,
                destination=destination,
                external_id=recommendation.id,
            )
            batch_id = self._find_batch_id(result)
            local_path = str((self.settings.downloads_dir / Path(destination)).resolve())
            status = "downloading" if batch_id else "queued_untracked"
            self.state.update_recommendation(
                recommendation_id,
                status=status,
                candidate_id=selected.candidate_id,
                slskd_batch_id=batch_id,
                local_path=local_path,
            )
            return {
                "ok": True,
                "status": status,
                "search_id": search_id,
                "batch_id": batch_id,
                "local_path": local_path,
                "candidate": selected.model_dump(mode="json"),
                "slskd": result,
            }
        except Exception:
            self.state.update_recommendation(recommendation_id, status="queue_failed")
            raise

    async def queue_candidate(
        self,
        candidate_id: str,
        *,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        destination: str | None = None,
    ) -> dict[str, Any]:
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        candidate = self.state.get_candidate(candidate_id)
        if not candidate:
            raise KeyError(f"Unknown or expired candidate: {candidate_id}")
        if destination:
            destination = safe_relative_destination(*Path(destination).parts)
        else:
            destination = safe_relative_destination(candidate.artist, candidate.album)
        result = await self.slskd.queue_album_candidate(
            candidate,
            destination=destination,
            external_id=stable_id("manual", candidate_id),
        )
        return {
            "rights": {"basis": rights.basis, "reference": rights.reference},
            "candidate": candidate.model_dump(mode="json"),
            "destination": destination,
            "batch_id": self._find_batch_id(result),
            "slskd": result,
        }

    async def import_recommendation(
        self,
        recommendation_id: str,
        *,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        recommendation = self.state.get_recommendation(recommendation_id)
        if not recommendation:
            raise KeyError(f"Unknown recommendation: {recommendation_id}")
        validate_rights(
            confirmed=True,
            basis=recommendation.rights_basis,
            reference=recommendation.rights_reference,
        )
        if not recommendation.local_path:
            raise RuntimeError("Recommendation has no download path")
        self.state.update_recommendation(recommendation_id, status="importing")
        try:
            result = await self.traxx.import_album_folder(
                recommendation.local_path,
                dry_run=dry_run,
                rights_confirmed=True,
                rights_basis=recommendation.rights_basis,
                rights_reference=recommendation.rights_reference,
            )
            if dry_run:
                status = "downloaded"
            elif result.get("unresolved_count", 0):
                status = "import_needs_configuration"
            elif result.get("imported_count", 0):
                status = "imported"
            else:
                status = "import_failed"
            self.state.update_recommendation(
                recommendation_id,
                status=status,
                traxx_result_json=result,
            )
            return result
        except Exception:
            self.state.update_recommendation(recommendation_id, status="import_failed")
            raise

    async def poll_downloads(self) -> dict[str, Any]:
        recommendations = self.state.list_recommendations(statuses=["downloading"], limit=200)
        completed: list[str] = []
        failed: list[str] = []
        active: list[str] = []
        errors: dict[str, str] = {}
        for recommendation in recommendations:
            if not recommendation.slskd_batch_id:
                continue
            try:
                batch = await self.slskd.get_download_batch(recommendation.slskd_batch_id)
                classification = classify_download_batch(batch)
                if classification == "complete":
                    self.state.update_recommendation(recommendation.id, status="downloaded")
                    completed.append(recommendation.id)
                    if self.settings.auto_import:
                        try:
                            await self.import_recommendation(recommendation.id, dry_run=False)
                        except Exception as exc:  # Keep polling other jobs.
                            errors[recommendation.id] = str(exc)
                elif classification == "failed":
                    self.state.update_recommendation(recommendation.id, status="download_failed")
                    failed.append(recommendation.id)
                else:
                    active.append(recommendation.id)
            except Exception as exc:
                errors[recommendation.id] = str(exc)
        return {
            "checked": len(recommendations),
            "completed": completed,
            "failed": failed,
            "active": active,
            "errors": errors,
        }

    async def scheduled_cycle(self) -> dict[str, Any]:
        result: dict[str, Any] = {"discovery": None, "queued": [], "poll": None, "errors": []}
        try:
            result["discovery"] = await self.discover()
        except Exception as exc:
            result["errors"].append(f"discovery: {exc}")

        if self.settings.auto_download and result["discovery"]:
            try:
                rights = validate_automation_rights(
                    authorized_library=self.settings.authorized_library,
                    basis=self.settings.default_rights_basis,
                    reference=self.settings.default_rights_reference,
                )
                for recommendation in result["discovery"]["recommendations"]:
                    try:
                        queued = await self.queue_recommendation(
                            recommendation["id"],
                            rights_confirmed=True,
                            rights_basis=rights.basis,
                            rights_reference=rights.reference,
                            minimum_score=50,
                        )
                        result["queued"].append(queued)
                    except Exception as exc:
                        result["errors"].append(f"queue {recommendation['id']}: {exc}")
            except RightsError as exc:
                result["errors"].append(f"automation-rights: {exc}")

        try:
            result["poll"] = await self.poll_downloads()
        except Exception as exc:
            result["errors"].append(f"poll: {exc}")
        return result

    async def connector_health(self) -> list[ConnectorHealth]:
        async def check(name: str, coroutine: Any) -> ConnectorHealth:
            try:
                data = await coroutine
                return ConnectorHealth(name=name, ok=True, detail="connected", data=data or {})
            except Exception as exc:
                return ConnectorHealth(name=name, ok=False, detail=str(exc))

        checks = [
            check("slskd", self.slskd.health()),
            check("traxx", self.traxx.health()),
        ]
        profile = self.state.get_selected_profile()
        if profile:
            async def spotify_health() -> dict[str, Any]:
                client = await self.spotify_for_profile(str(profile["id"]))
                me = await client.current_user()
                self.state.update_profile_token(str(profile["id"]), self.cipher.encrypt(client.token))
                return {
                    "id": me.get("id"),
                    "display_name": me.get("display_name"),
                }

            checks.append(check("spotify", spotify_health()))
        else:
            async def no_spotify() -> Any:
                raise RuntimeError("no Spotify profile connected")

            checks.append(check("spotify", no_spotify()))
        return await asyncio.gather(*checks)

    @staticmethod
    def _find_batch_id(payload: Any) -> str | None:
        if isinstance(payload, dict):
            direct = get_case_insensitive(payload, "batchId", "requestedBatchId", "id")
            if direct is not None:
                return str(direct)
        for mapping in walk_dicts(payload):
            if any(key.casefold() in {"files", "username", "userid"} for key in mapping):
                value = get_case_insensitive(mapping, "batchId", "requestedBatchId", "id")
                if value is not None:
                    return str(value)
        return None


def classify_download_batch(payload: Any) -> str:
    states: list[str] = []
    byte_complete = 0
    byte_seen = 0
    for mapping in walk_dicts(payload):
        filename = get_case_insensitive(mapping, "filename", "fileName")
        state = get_case_insensitive(mapping, "state", "status")
        if filename and state is not None:
            states.append(str(state).replace(" ", "").casefold())
        size = get_case_insensitive(mapping, "size", "fileSize")
        transferred = get_case_insensitive(
            mapping,
            "bytesTransferred",
            "bytesDownloaded",
            "bytesComplete",
        )
        try:
            size_int = int(size)
            transferred_int = int(transferred)
        except (TypeError, ValueError):
            continue
        if size_int > 0:
            byte_seen += 1
            if transferred_int >= size_int:
                byte_complete += 1

    if states:
        if all(state in COMPLETE_STATES for state in states):
            return "complete"
        if any(state in ACTIVE_STATES for state in states):
            return "active"
        if any(state in FAILED_STATES for state in states):
            return "failed"
    if byte_seen and byte_seen == byte_complete:
        return "complete"

    top_state = ""
    if isinstance(payload, dict):
        top_state = str(get_case_insensitive(payload, "state", "status", default=""))
        top_state = top_state.replace(" ", "").casefold()
    if top_state in COMPLETE_STATES:
        return "complete"
    if top_state in FAILED_STATES:
        return "failed"
    return "active"
