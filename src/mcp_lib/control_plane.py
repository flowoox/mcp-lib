from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Settings, get_settings
from .pipeline import MusicPipeline
from .spotify import (
    SpotifyClient,
    create_authorization_url,
    create_pkce_pair,
    exchange_authorization_code,
)
from .state import StateStore

LOGGER = logging.getLogger(__name__)
security = HTTPBasic(auto_error=False)


def redirect_with_message(message: str, *, error: bool = False) -> RedirectResponse:
    query = urlencode({"error" if error else "message": message})
    return RedirectResponse(f"/?{query}", status_code=status.HTTP_303_SEE_OTHER)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    state_store = StateStore(settings.state_db)
    pipeline = MusicPipeline(settings, state_store)
    package_dir = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(package_dir / "templates"))

    async def scheduled_cycle() -> None:
        LOGGER.info("Starting scheduled music discovery cycle")
        result = await pipeline.scheduled_cycle()
        if result.get("errors"):
            LOGGER.warning("Scheduled cycle completed with errors: %s", result["errors"])

    async def poll_cycle() -> None:
        try:
            await pipeline.poll_downloads()
        except Exception:
            LOGGER.exception("Download polling failed")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler: AsyncIOScheduler | None = None
        if settings.schedule_enabled:
            scheduler = AsyncIOScheduler(timezone=settings.tz)
            scheduler.add_job(
                scheduled_cycle,
                trigger="cron",
                hour=settings.schedule_hour,
                minute=settings.schedule_minute,
                id="daily-discovery",
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            scheduler.add_job(
                poll_cycle,
                trigger="interval",
                seconds=settings.poll_interval_seconds,
                id="download-poll",
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            scheduler.start()
            app.state.scheduler = scheduler
        yield
        if scheduler:
            scheduler.shutdown(wait=False)

    app = FastAPI(
        title="MCP Music Automation",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.state_store = state_store
    app.state.pipeline = pipeline
    app.mount(
        "/static",
        StaticFiles(directory=str(package_dir / "static")),
        name="static",
    )

    def require_auth(
        credentials: Annotated[HTTPBasicCredentials | None, Depends(security)],
    ) -> None:
        expected_username = settings.dashboard_username
        expected_password = settings.dashboard_password
        if not expected_username and not expected_password:
            return
        valid = bool(
            credentials
            and secrets.compare_digest(credentials.username, expected_username or "")
            and secrets.compare_digest(credentials.password, expected_password or "")
        )
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Basic"},
            )

    protected = [Depends(require_auth)]

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": "mcp-lib-control-plane",
            "schedule_enabled": settings.schedule_enabled,
        }

    @app.get("/", response_class=HTMLResponse, dependencies=protected)
    async def index(
        request: Request,
        message: str = Query(default=""),
        error: str = Query(default=""),
    ) -> HTMLResponse:
        profiles = state_store.list_profiles()
        selected = state_store.get_selected_profile()
        recommendations = state_store.list_recommendations(
            profile_id=str(selected["id"]) if selected else None,
            limit=100,
        )
        context = {
            "request": request,
            "profiles": profiles,
            "selected_profile": selected,
            "recommendations": recommendations,
            "message": message,
            "error": error,
            "schedule": f"{settings.schedule_hour:02d}:{settings.schedule_minute:02d}",
            "albums_per_day": settings.discovery_albums_per_day,
            "auto_download": settings.auto_download,
            "auto_import": settings.auto_import,
            "authorized_library": settings.authorized_library,
            "spotify_configured": bool(settings.spotify_client_id),
            "traxx_configured": bool(settings.traxx_url and settings.traxx_token),
            "slskd_configured": bool(settings.slskd_url and settings.slskd_api_key),
        }
        return templates.TemplateResponse(request=request, name="index.html", context=context)

    @app.get("/api/connectors/health", dependencies=protected)
    async def connector_health() -> list[dict[str, Any]]:
        results = await pipeline.connector_health()
        return [result.model_dump(mode="json") for result in results]

    @app.post("/api/discover", dependencies=protected)
    async def discover_now(
        profile_id: Annotated[str | None, Form()] = None,
        limit: Annotated[int | None, Form()] = None,
    ) -> RedirectResponse:
        try:
            result = await pipeline.discover(profile_id=profile_id, limit=limit)
            count = len(result.get("recommendations", []))
            return redirect_with_message(f"{count} neue Albumempfehlungen erstellt.")
        except Exception as exc:
            LOGGER.exception("Manual discovery failed")
            return redirect_with_message(str(exc), error=True)

    @app.post("/api/poll", dependencies=protected)
    async def poll_now() -> RedirectResponse:
        try:
            result = await pipeline.poll_downloads()
            return redirect_with_message(
                f"Downloads geprüft: {result['checked']}, abgeschlossen: {len(result['completed'])}."
            )
        except Exception as exc:
            LOGGER.exception("Manual polling failed")
            return redirect_with_message(str(exc), error=True)

    @app.post("/api/scheduled-cycle", dependencies=protected)
    async def run_scheduled_cycle() -> JSONResponse:
        result = await pipeline.scheduled_cycle()
        return JSONResponse(result)

    @app.get("/spotify/connect", dependencies=protected)
    async def spotify_connect() -> RedirectResponse:
        if not settings.spotify_client_id:
            return redirect_with_message("SPOTIFY_CLIENT_ID ist nicht konfiguriert.", error=True)
        state = secrets.token_urlsafe(32)
        verifier, challenge = create_pkce_pair()
        state_store.save_oauth_state(state, verifier)
        url = create_authorization_url(
            client_id=settings.spotify_client_id,
            redirect_uri=settings.spotify_redirect_uri,
            scopes=settings.spotify_scopes,
            state=state,
            code_challenge=challenge,
        )
        return RedirectResponse(url, status_code=status.HTTP_302_FOUND)

    @app.get("/spotify/callback", dependencies=protected)
    async def spotify_callback(
        code: str = Query(default=""),
        state: str = Query(default=""),
        error: str = Query(default=""),
    ) -> RedirectResponse:
        if error:
            return redirect_with_message(f"Spotify hat die Verbindung abgelehnt: {error}", error=True)
        verifier = state_store.pop_oauth_state(state)
        if not verifier or not code:
            return redirect_with_message("Ungültiger oder abgelaufener Spotify-OAuth-Status.", error=True)
        try:
            token = await exchange_authorization_code(
                client_id=settings.spotify_client_id,
                redirect_uri=settings.spotify_redirect_uri,
                code=code,
                code_verifier=verifier,
            )
            spotify = SpotifyClient(client_id=settings.spotify_client_id, token=token)
            me = await spotify.current_user()
            state_store.upsert_profile(
                spotify_user_id=str(me.get("id") or ""),
                display_name=str(me.get("display_name") or me.get("id") or "Spotify user"),
                email=str(me.get("email") or ""),
                encrypted_token=pipeline.cipher.encrypt(spotify.token),
            )
            return redirect_with_message(
                f"Spotify-Profil {me.get('display_name') or me.get('id')} verbunden."
            )
        except Exception as exc:
            LOGGER.exception("Spotify callback failed")
            return redirect_with_message(str(exc), error=True)

    @app.post("/profiles/select", dependencies=protected)
    async def select_profile(profile_id: Annotated[str, Form()]) -> RedirectResponse:
        try:
            state_store.set_selected_profile(profile_id)
            return redirect_with_message("Spotify-Profil ausgewählt.")
        except Exception as exc:
            return redirect_with_message(str(exc), error=True)

    @app.post("/recommendations/{recommendation_id}/queue", dependencies=protected)
    async def queue_recommendation(
        recommendation_id: str,
        rights_confirmed: Annotated[bool, Form()] = False,
        rights_basis: Annotated[str, Form()] = "",
        rights_reference: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        try:
            result = await pipeline.queue_recommendation(
                recommendation_id,
                rights_confirmed=rights_confirmed,
                rights_basis=rights_basis,
                rights_reference=rights_reference,
            )
            return redirect_with_message(f"Albumstatus: {result['status']}.")
        except Exception as exc:
            LOGGER.exception("Queue recommendation failed")
            return redirect_with_message(str(exc), error=True)

    @app.post("/recommendations/{recommendation_id}/import", dependencies=protected)
    async def import_recommendation(
        recommendation_id: str,
        dry_run: Annotated[bool, Form()] = False,
    ) -> RedirectResponse:
        try:
            result = await pipeline.import_recommendation(recommendation_id, dry_run=dry_run)
            if dry_run:
                message = f"Importprüfung erfolgreich: {result.get('track_count', 0)} Tracks."
            else:
                message = (
                    f"Traxx-Import: {result.get('imported_count', 0)} importiert, "
                    f"{result.get('unresolved_count', 0)} offen."
                )
            return redirect_with_message(message)
        except Exception as exc:
            LOGGER.exception("Import recommendation failed")
            return redirect_with_message(str(exc), error=True)

    return app


def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run(
        create_app(settings),
        host=settings.control_host,
        port=settings.control_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
