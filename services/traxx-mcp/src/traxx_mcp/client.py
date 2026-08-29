from __future__ import annotations

import base64
import contextlib
import json
import mimetypes
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from uuid import uuid4

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import normalize_text, resolve_contained_path
from mcp_common.rights import validate_rights
from mcp_common.store import AtomicJsonStore

from .config import RuntimeConfig
from .malware import ClamAvScanner, MalwareDetectedError
from .metadata import (
    AUDIO_EXTENSIONS,
    TrackHint,
    assign_track_hints,
    clean_title_from_filename,
    cover_mime_type,
    ensure_audio_metadata,
    find_local_cover,
    inspect_audio_file,
    verify_assignment,
    verify_release,
    verify_release_coverage,
)
from .tus import TusUnsupported, TusUploader, TusUploadResult, recursive_find


class TraxxError(RuntimeError):
    """Traxx failure with enough transport detail for mutation cleanup.

    A client-side timeout after a POST is fundamentally different from a 422
    response: the former may have lost the success response after Traxx
    committed, while the latter positively rejected the request.  Import
    cleanup must retain uploaded files in the first case and may remove them in
    the second.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        method: str = "",
        path: str = "",
        mutation_ambiguous: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.method = method.upper()
        self.path = path
        self.mutation_ambiguous = mutation_ambiguous

    @property
    def definitively_rejected(self) -> bool:
        """Whether Traxx positively refused this request before mutation.

        Ordinary 4xx API validation/auth/conflict responses are definitive.
        Request Timeout is deliberately excluded because an intermediary can
        emit it while the origin is still completing the mutation.
        """

        return (
            self.status_code is not None
            and 400 <= self.status_code < 500
            and self.status_code != 408
            and not self.mutation_ambiguous
        )


# The instance publishes the upload types it accepts in its bootstrap
# settings: audio belongs to "media", images to "artwork". Any other value —
# "track" was the earlier guess — makes the server answer 500 before the first
# byte is sent.
UPLOAD_TYPE_ALIASES = {
    "track": "media",
    "tracks": "media",
    "audio": "media",
    "media": "media",
    "image": "artwork",
    "cover": "artwork",
    "artwork": "artwork",
}

# Tried in order after whatever is configured. The first one is where BeMusic
# actually mounts its TUS server.
TUS_ENDPOINT_CANDIDATES = ("/api/v1/tus/upload", "/api/v1/tus", "/tus")


def normalize_genres(value: Any, fallback: list[str] | None = None) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        output: list[str] = []
        for item in value:
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                name = get_case_insensitive(
                    item,
                    "name",
                    "display_name",
                    "displayName",
                    default="",
                )
            else:
                name = str(item)
            name = str(name).strip()
            if name and name not in output:
                output.append(name)
        return output or list(fallback or [])
    return list(fallback or [])


def iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_dicts(child)


def extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "items", "artists", "albums", "tracks"):
        value = get_case_insensitive(payload, key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    pagination = get_case_insensitive(payload, "pagination")
    if isinstance(pagination, dict):
        return extract_items(pagination)
    for mapping in iter_dicts(payload):
        value = get_case_insensitive(mapping, "data", "items")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def select_resource_items(payload: Any, resource: str) -> list[dict[str, Any]]:
    """Pull one named bucket out of a Traxx search answer.

    The search route nests its answer as ``results.<resource>.data`` and
    paginates every bucket on its own. A generic "first data list wins" walk
    lands in the tracks bucket whichever resource was asked for, so an album
    lookup came back empty and the importer created the album again on every
    run. Reading the bucket by name is what makes the lookup a lookup.
    """
    for container in (get_case_insensitive(payload, "results"), payload):
        if not isinstance(container, dict):
            continue
        bucket = get_case_insensitive(container, resource)
        if isinstance(bucket, list):
            return [item for item in bucket if isinstance(item, dict)]
        if isinstance(bucket, dict):
            return extract_items(bucket)
    return extract_items(payload)


def _liked_artist_names(item: dict[str, Any], resource: str) -> list[str]:
    """Artist names behind one liked thing, whatever kind it is."""
    if resource == "artists":
        name = str(get_case_insensitive(item, "name", default="") or "").strip()
        return [name] if name else []
    names: list[str] = []
    artists = get_case_insensitive(item, "artists", "artist")
    if isinstance(artists, dict):
        artists = [artists]
    for entry in artists if isinstance(artists, list) else []:
        if isinstance(entry, dict):
            name = str(get_case_insensitive(entry, "name", default="") or "").strip()
        else:
            name = str(entry or "").strip()
        if name and name not in names:
            names.append(name)
    if not names:
        album = get_case_insensitive(item, "album")
        if isinstance(album, dict):
            return _liked_artist_names(album, "albums")
    return names


def describe_cover(local_cover: Path | None, url: str) -> dict[str, Any]:
    """What became of the album art, in a form the operator can act on.

    Reported, not enforced: an album without a sleeve is still the album. But
    nothing downstream can invent one, and a blank tile in the library is
    exactly the kind of defect nobody goes looking for — so if it did not
    happen, it has to be said here.
    """
    return {
        "ok": bool(url),
        "source": (
            "Datei im Ordner"
            if local_cover
            else ("externe Adresse" if url else "keine")
        ),
        "url": url,
        "warning": (
            ""
            if url
            else (
                "Kein Cover: der Ordner enthält kein Bild und es wurde keine "
                "Bildadresse mitgegeben. Das Album erscheint in Traxx ohne "
                "Titelbild."
            )
        ),
    }


def target_user_id(value: str) -> str:
    """Validate a Traxx user id before it becomes part of an API path."""
    user_id = str(value).strip()
    if user_id and (not user_id.isascii() or not user_id.isdigit()):
        raise TraxxError(f"Not a Traxx user id: {value!r}")
    return user_id


class TraxxClient:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        downloads_dir: Path,
        import_ledger: AtomicJsonStore | None = None,
        actor_token: str = "",
        malware_scanner: ClamAvScanner | None = None,
    ):
        self.config = config
        self.downloads_dir = downloads_dir
        self.import_ledger = import_ledger
        # An actor token replaces only the Authorization bearer, so requests
        # run as a specific Traxx user while base_url, TLS verification,
        # proxy headers and timeouts stay those of the shared configuration.
        self.actor_token = actor_token
        self.malware_scanner = malware_scanner
        # Probed once per client, then reused for every file of an album.
        self._tus_endpoint = ""
        self._upload_limits: dict[str, int] | None = None

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        token = self.actor_token or self.config.token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # Applied last so a proxy header cannot be silently dropped, but the
        # Authorization header stays under this client's control.
        for key, value in (self.config.extra_headers or {}).items():
            if key.strip() and key.strip().casefold() != "authorization":
                headers[key.strip()] = str(value)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        allow_error: bool = False,
    ) -> Any:
        if not self.config.base_url:
            raise TraxxError("Traxx URL is not configured")
        normalized_method = method.upper()
        try:
            async with httpx.AsyncClient(
                base_url=self.config.base_url,
                headers=self.headers,
                verify=self.config.verify_tls,
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            mutation_ambiguous = normalized_method not in {"GET", "HEAD", "OPTIONS"}
            raise TraxxError(
                f"Traxx {normalized_method} {path} transport failed: {exc}",
                method=normalized_method,
                path=path,
                mutation_ambiguous=mutation_ambiguous,
            ) from exc
        if response.status_code >= 400 and not allow_error:
            raise TraxxError(
                f"Traxx {normalized_method} {path} failed ({response.status_code}): "
                f"{response.text[:1400]}",
                status_code=response.status_code,
                method=normalized_method,
                path=path,
                mutation_ambiguous=response.status_code >= 500
                or response.status_code == 408,
            )
        body: Any = None
        if response.content:
            try:
                body = response.json()
            except ValueError:
                body = {"text": response.text[:2000]}
        if allow_error:
            return {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": body,
            }
        return body

    async def health(self) -> dict[str, Any]:
        """Check reachability and the token against a route that exists.

        ``/users/me/playlists`` is part of the documented API and requires
        authentication, so the outcome separates three cases that used to look
        identical: an edge that never forwarded the request, a token the
        instance rejects, and a working connection.
        """
        probe = "/api/v1/users/me/playlists"
        result = await self.request("GET", probe, params={"perPage": 1}, allow_error=True)
        status = int(result.get("status") or 0)
        headers = {str(k).casefold(): str(v) for k, v in (result.get("headers") or {}).items()}
        is_html = "html" in headers.get("content-type", "").casefold()
        if 200 <= status < 300:
            return {
                "ok": True,
                "base_url": self.config.base_url,
                "api": probe,
                "response_type": type(result.get("body")).__name__,
            }
        if status == 404:
            # BeMusic serves its own HTML 404 for anything that matches no API
            # route, so this says the URL was wrong, not that a proxy blocked it.
            raise TraxxError(
                f"Traxx GET {probe} returned 404 at {self.config.base_url}{probe}. "
                "The request reached an application that has no such route. Check "
                "that the configured Traxx URL is the bare origin, for example "
                "https://traxx.example.ch, without a trailing /api or /api/v1 — "
                "those are added by this connector. Run diagnose_connection to see "
                "the exact URL that was called."
            )
        if is_html and status in {401, 403}:
            # For auth failures BeMusic answers JSON when asked for JSON, so an
            # HTML page at this status came from something in front of it.
            raise TraxxError(
                f"Traxx GET {probe} returned an HTML error page with status {status}. "
                "An authentication failure from the API itself would be JSON, so "
                "this came from a proxy or WAF in front of it. Allow this client "
                "through there, for example with a shared header configured via "
                "extra_headers."
            )
        if status in {401, 403}:
            raise TraxxError(
                f"Traxx GET {probe} was rejected ({status}). The instance was reached "
                "but the API token was refused. Create a token under account settings "
                "and check that it belongs to an account with the required rights."
            )
        raise TraxxError(
            f"Traxx GET {probe} failed ({status}): "
            f"{str(result.get('body'))[:600]}"
        )

    async def diagnose_connection(self) -> dict[str, Any]:
        """Report the URLs this client builds and what each one answers.

        Written to be compared against a manual curl: if the effective URL here
        differs from the one that works by hand, the configuration is what
        differs, not the network.
        """
        tus = self.config.tus_endpoint or "/api/v1/tus/"
        probes: list[tuple[str, str]] = [
            ("GET", "/api/v1/users/me/playlists"),
            ("GET", "/api/v1/genres"),
            ("GET", "/api/v1/search"),
            # TUS servers answer OPTIONS with their protocol headers, which is
            # how the real upload endpoint identifies itself.
            ("OPTIONS", tus),
            ("OPTIONS", "/api/v1/tus"),
            ("OPTIONS", "/tus"),
            ("OPTIONS", "/api/v1/uploads/tus"),
            ("OPTIONS", "/files/tus"),
            ("POST", "/api/v1/uploads"),
        ]
        results: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            verify=self.config.verify_tls,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
        ) as client:
            for method, path in probes:
                entry: dict[str, Any] = {"method": method, "path": path}
                try:
                    response = await client.request(method, path)
                except Exception as exc:
                    entry["error"] = f"{type(exc).__name__}: {exc}"
                    results.append(entry)
                    continue
                headers = {k.casefold(): v for k, v in response.headers.items()}
                entry.update(
                    {
                        "effective_url": str(response.request.url),
                        "status": response.status_code,
                        "content_type": headers.get("content-type", ""),
                        "tus_resumable": headers.get("tus-resumable", ""),
                        "tus_version": headers.get("tus-version", ""),
                        "location": headers.get("location", ""),
                        "looks_like_tus": bool(
                            headers.get("tus-resumable") or headers.get("tus-version")
                        ),
                    }
                )
                results.append(entry)
        return {
            "base_url": self.config.base_url,
            "token_configured": bool(self.config.token),
            "extra_header_names": sorted(self.config.extra_headers or {}),
            "configured_tus_endpoint": tus,
            "probes": results,
            "tus_candidates": [
                item["path"] for item in results if item.get("looks_like_tus")
            ],
        }

    async def search_resource(
        self, resource: str, name: str, *, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Look records up by name through the documented search route.

        The API exposes no paginated collection route for artists, albums or
        tracks — only reads by id — so search is the only supported way to
        resolve a name to an id.
        """
        payload = await self.request(
            "GET", "/api/v1/search", params={"query": name, "limit": limit}
        )
        return select_resource_items(payload, resource)

    async def list_resource(
        self,
        resource: str,
        *,
        page: int = 1,
        per_page: int = 20,
        query: str = "",
    ) -> Any:
        params: dict[str, Any] = {"page": page, "perPage": per_page}
        if query:
            params["query"] = query
        return await self.request("GET", f"/api/v1/{resource}", params=params)

    async def refresh_library_channels(self) -> dict[str, Any]:
        """Refresh local auto channels and invalidate every nested container.

        BeMusic caches channels containing other channels for 24 hours. Album
        and track APIs do not invalidate that cache, so a successful import can
        remain invisible on the homepage. Refresh the dynamic local sections
        and touch each nested container with an internal revision value. The
        application ignores that value, but saving it advances ``updated_at``
        and therefore changes the cache key immediately.
        """
        payload = await self.request(
            "GET", "/api/v1/channel", params={"page": 1, "perPage": 100}
        )
        revision = datetime.now(UTC).isoformat()
        refreshed: list[int] = []
        errors: list[str] = []
        for channel in extract_items(payload):
            raw_id = get_case_insensitive(channel, "id")
            try:
                channel_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            config = get_case_insensitive(channel, "config", default={})
            config = config if isinstance(config, dict) else {}
            is_local_auto = (
                get_case_insensitive(config, "contentType") == "autoUpdate"
                and get_case_insensitive(
                    config, "autoUpdateProvider", default="local"
                )
                == "local"
            )
            is_nested_container = (
                get_case_insensitive(config, "contentModel") == "channel"
            )
            if not is_local_auto and not is_nested_container:
                continue
            body = (
                {}
                if is_local_auto
                else {"channelConfig": {"radarLibraryRevision": revision}}
            )
            try:
                await self.request(
                    "POST",
                    f"/api/v1/channel/{channel_id}/update-content",
                    json=body,
                )
                refreshed.append(channel_id)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"channel {channel_id}: {exc}")
        return {"refreshed": refreshed, "errors": errors, "revision": revision}

    async def list_liked(
        self,
        resource: str,
        *,
        page: int = 1,
        per_page: int = 50,
        user_id: str = "",
    ) -> Any:
        """List what an account has liked. Empty ``user_id`` means our own.

        The same route answers for any user id, not only for "me", so the
        taste of every member can be read with one service token instead of
        asking each of them for one.
        """
        allowed = {"artists", "albums", "tracks"}
        if resource not in allowed:
            raise TraxxError(f"list_liked supports {sorted(allowed)}, not {resource!r}")
        who = target_user_id(user_id) or "me"
        return await self.request(
            "GET",
            f"/api/v1/users/{who}/liked-{resource}",
            params={"page": page, "perPage": per_page},
        )

    async def list_members(self, *, page: int = 1, per_page: int = 50) -> list[dict[str, Any]]:
        """Everyone with an account on this instance, with their address.

        The address is what ties a listener here to the same person on
        Spotify; without it the two halves of someone's taste stay separate.
        """
        payload = await self.request(
            "GET", "/api/v1/users", params={"page": page, "perPage": per_page}
        )
        members: list[dict[str, Any]] = []
        for item in extract_items(payload):
            identifier = get_case_insensitive(item, "id")
            if identifier is None:
                continue
            members.append(
                {
                    "id": str(identifier),
                    "name": str(get_case_insensitive(item, "name", default="") or ""),
                    "email": str(get_case_insensitive(item, "email", default="") or ""),
                    "created_at": str(
                        get_case_insensitive(item, "created_at", default="") or ""
                    ),
                }
            )
        return members

    async def member_taste(
        self, user_id: str = "", *, pages: int = 2, per_page: int = 50
    ) -> dict[str, Any]:
        """What one listener has marked as theirs, weighted by how strong the
        signal is.

        A liked artist says more than a liked album, which says more than a
        single liked track — the narrower the mark, the less of the artist it
        vouches for.
        """
        weights = {"artists": 5.0, "albums": 2.0, "tracks": 1.0}
        totals: dict[str, dict[str, Any]] = {}
        counts: dict[str, int] = {}
        errors: list[str] = []
        for resource, weight in weights.items():
            for page in range(1, max(1, pages) + 1):
                try:
                    payload = await self.list_liked(
                        resource, page=page, per_page=per_page, user_id=user_id
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{resource}: {exc}")
                    break
                items = extract_items(payload)
                if not items:
                    break
                counts[resource] = counts.get(resource, 0) + len(items)
                for item in items:
                    for name in _liked_artist_names(item, resource):
                        entry = totals.setdefault(
                            name, {"name": name, "weight": 0.0, "signals": 0}
                        )
                        entry["weight"] += weight
                        entry["signals"] += 1
        ranked = sorted(
            totals.values(), key=lambda item: float(item["weight"]), reverse=True
        )
        return {
            "user_id": str(user_id or "me"),
            "liked": counts,
            "artists": ranked,
            "errors": errors,
        }

    async def upload_limits(self) -> dict[str, int]:
        """The largest file each upload type accepts, as the instance says.

        Read from the page the web app bootstraps itself with, because the
        limit lives in the instance settings and is not part of the documented
        API. Measured: it changed from 600 MB to 10 MB between two runs, which
        turned every album import into a stack of 422s.
        """
        if self._upload_limits is not None:
            return self._upload_limits
        limits: dict[str, int] = {}
        try:
            async with httpx.AsyncClient(
                base_url=self.config.base_url,
                verify=self.config.verify_tls,
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(
                    "/",
                    headers={
                        # The bootstrap block is only served to something that
                        # looks like a browser; a crawler gets a plain page.
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/126.0.0.0 Safari/537.36"
                        )
                    },
                )
            marker = "window.bootstrapData = "
            start = response.text.index(marker) + len(marker)
            data, _ = json.JSONDecoder().raw_decode(response.text[start:])
            for name, entry in (data.get("uploading_types") or {}).items():
                size = entry.get("max_file_size") if isinstance(entry, dict) else None
                if size:
                    limits[str(name)] = int(size)
        except Exception:  # noqa: BLE001
            # Not knowing the limit is not an error; it only means the check
            # below cannot be made and the upload decides instead.
            limits = {}
        self._upload_limits = limits
        return limits

    async def check_upload_sizes(
        self, files: list[Path], *, upload_type: str = "media"
    ) -> str:
        """Say up front whether these files can be uploaded at all.

        Without this the importer created the artist and the album, then failed
        on every single track and left an empty album behind — nineteen of them
        on the live instance before this was found.
        """
        limits = await self.upload_limits()
        limit = limits.get(UPLOAD_TYPE_ALIASES.get(upload_type, upload_type), 0)
        if not limit:
            return ""
        too_big = [path for path in files if path.stat().st_size > limit]
        if not too_big:
            return ""
        largest = max(too_big, key=lambda path: path.stat().st_size)
        # A suspiciously small limit is usually not a decision somebody made.
        # Measured on this instance: the encrypted "uploading" setting became
        # unreadable after the APP_KEY changed, the application fell back to
        # its built-in defaults without saying so, and the limit silently
        # dropped from 512 MB to 10 MB. Naming that possibility saves the next
        # person the two hours it cost to find.
        if limit <= 10 * 1024 * 1024:
            return (
                f"Traxx meldet ein Upload-Limit von nur "
                f"{limit / 1_000_000:.0f} MB — das ist der eingebaute "
                "Standardwert. Das deutet darauf hin, dass die verschlüsselte "
                "Einstellung „uploading“ nicht mehr lesbar ist (APP_KEY "
                "gewechselt): BeMusic fällt dann still auf Voreinstellungen "
                "zurück, und aus demselben Grund verlieren auch alle Tracks "
                "ihre Storage-URL und lassen sich nicht mehr abspielen. Prüfe "
                "das, bevor du das Limit von Hand hochsetzt."
            )
        return (
            f"{len(too_big)} von {len(files)} Dateien überschreiten das "
            f"Upload-Limit dieser Traxx-Instanz von {limit / 1_000_000:.0f} MB — "
            f"die grösste ist „{largest.name}“ mit "
            f"{largest.stat().st_size / 1_000_000:.0f} MB. Das ist eine "
            "Einstellung auf der Traxx-Seite (Einrichtung → Uploads → maximale "
            "Dateigrösse), nicht am Radar. Bis sie erhöht ist, kann kein "
            "verlustfreies Album importiert werden."
        )

    async def _resolve_tus_endpoint(self) -> str:
        """Find the path that really speaks TUS on this instance.

        BeMusic answers OPTIONS on any unknown path with its single-page app,
        so a 200 says nothing. Only the ``Tus-Resumable`` header separates the
        upload route from that catch-all, which is why a configured
        ``/api/v1/tus/`` looked reachable while every upload failed.
        """
        if self._tus_endpoint:
            return self._tus_endpoint
        if not self.config.base_url:
            raise TraxxError("Traxx URL is not configured")
        checked: list[str] = []
        seen: set[str] = set()
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            verify=self.config.verify_tls,
            timeout=self.config.timeout_seconds,
            follow_redirects=True,
        ) as client:
            for candidate in (self.config.tus_endpoint, *TUS_ENDPOINT_CANDIDATES):
                path = candidate.strip()
                if not path:
                    continue
                if not path.startswith("/"):
                    path = f"/{path}"
                path = path.rstrip("/") or "/"
                if path in seen:
                    continue
                seen.add(path)
                try:
                    response = await client.request("OPTIONS", path)
                except httpx.HTTPError as exc:
                    checked.append(f"{path}: {type(exc).__name__}")
                    continue
                headers = {k.casefold(): v for k, v in response.headers.items()}
                if headers.get("tus-resumable") or headers.get("tus-version"):
                    self._tus_endpoint = path
                    return path
                checked.append(f"{path}: {response.status_code} without TUS headers")
        raise TusUnsupported(
            "No TUS upload route answered on this Traxx instance. Tried "
            + "; ".join(checked),
            status_code=0,
        )

    async def upload_file(
        self,
        path: Path,
        *,
        upload_type: str = "track",
    ) -> TusUploadResult:
        resolved_type = UPLOAD_TYPE_ALIASES.get(
            upload_type.strip().casefold(), upload_type.strip()
        )
        try:
            endpoint_path = await self._resolve_tus_endpoint()
        except TusUnsupported:
            # Resumable upload is the better transport for album-sized files,
            # but not every instance offers it. Falling back keeps those
            # importable instead of failing every track.
            return await self._upload_multipart(path, upload_type=resolved_type)
        uploader = TusUploader(
            endpoint=urljoin(f"{self.config.base_url}/", endpoint_path.lstrip("/")),
            headers=self.headers,
            verify_tls=self.config.verify_tls,
            chunk_size=self.config.upload_chunk_size,
            timeout=max(300, self.config.timeout_seconds),
        )
        result = await uploader.upload(
            path,
            upload_type=resolved_type,
            # The web app sends an opaque client-side id here; the stored name
            # comes from clientName, so any stable value does.
            extra_metadata={
                "name": base64.b64encode(str(uuid4()).encode()).decode("ascii")
            },
        )
        return await self._finalize_tus_upload(result, endpoint_path=endpoint_path)

    async def _finalize_tus_upload(
        self, upload: TusUploadResult, *, endpoint_path: str
    ) -> TusUploadResult:
        """Turn a finished TUS upload into a FileEntry.

        TUS only moves the bytes. The row a track can point at is created by a
        second call — the one the web app makes in its ``onSuccess`` handler.
        Without it the audio sits on disk with no id and no URL, which is what
        made every track come back as "no FileEntry id was exposed".
        """
        key = upload.upload_url.rstrip("/").rsplit("/", 1)[-1]
        if not key:
            return upload
        entries_path = f"{endpoint_path.rsplit('/', 1)[0]}/entries"
        body = await self.request("POST", entries_path, json={"uploadKey": key})
        entry = get_case_insensitive(body, "fileEntry", "file_entry", default=body)
        if isinstance(entry, dict):
            entry_id = get_case_insensitive(entry, "id")
            if entry_id is not None:
                upload.file_entry_id = str(entry_id)
            file_url = get_case_insensitive(entry, "url")
            if file_url:
                upload.file_url = str(file_url)
        if isinstance(body, dict):
            upload.response_json = body
        return upload

    async def _upload_multipart(
        self, path: Path, *, upload_type: str
    ) -> TusUploadResult:
        """Ordinary single-request upload, for instances without a TUS route.

        Returns the same result shape as the resumable path so callers do not
        have to know which transport carried the file.
        """
        payload = path.read_bytes()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            verify=self.config.verify_tls,
            timeout=max(300, self.config.timeout_seconds),
        ) as client:
            response = await client.post(
                "/api/v1/uploads",
                files={"file": (path.name, payload, mime)},
                data={
                    "uploadType": upload_type,
                    "clientName": path.name,
                    "clientMime": mime,
                    "clientSize": str(len(payload)),
                    "clientExtension": path.suffix.lstrip("."),
                },
            )
        if response.status_code == 403:
            raise TraxxError(
                "Traxx refused the upload (403). The API account may create "
                "music but not files: grant it the 'files.create' permission, "
                "then retry. Nothing else about the import needs to change."
            )
        if response.status_code >= 400:
            raise TraxxError(
                f"Traxx upload failed ({response.status_code}): {response.text[:800]}"
            )
        body = response.json() if "json" in response.headers.get("content-type", "") else {}
        entry = get_case_insensitive(body, "fileEntry", "file_entry", default=body)
        entry_id = get_case_insensitive(entry, "id") if isinstance(entry, dict) else None
        return TusUploadResult(
            upload_url=str(response.url),
            bytes_uploaded=len(payload),
            file_entry_id=str(entry_id) if entry_id is not None else None,
            file_url=(
                get_case_insensitive(entry, "url") if isinstance(entry, dict) else None
            ),
            create_status=response.status_code,
            final_status=response.status_code,
            response_json=body if isinstance(body, dict) else None,
        )

    def resolve_file_url(self, upload: TusUploadResult) -> str | None:
        if upload.file_url:
            return upload.file_url
        if self.config.file_url_template and upload.file_entry_id:
            return self.config.file_url_template.format(
                file_entry_id=upload.file_entry_id,
                upload_url=upload.upload_url,
                base_url=self.config.base_url,
            )
        return None

    async def discover_file_entry(self, upload: TusUploadResult) -> dict[str, Any]:
        result: dict[str, Any] = {
            "file_entry_id": upload.file_entry_id,
            "file_url": self.resolve_file_url(upload),
            "probes": [],
        }
        if not upload.file_entry_id or result["file_url"]:
            # A finalized TUS upload already carries both, and the extra probes
            # would only risk overwriting them from a differently shaped route.
            return result
        paths = (
            f"/api/v1/file-entries/{upload.file_entry_id}",
            f"/api/v1/files/{upload.file_entry_id}",
        )
        for path in paths:
            response = await self.request("GET", path, allow_error=True)
            result["probes"].append(
                {
                    "path": path,
                    "status": response["status"],
                    "body": response["body"],
                }
            )
            if response["status"] < 400 and isinstance(response["body"], dict):
                body = response["body"]
                found_id = recursive_find(
                    body,
                    {"fileentryid", "file_entry_id", "id"},
                )
                found_url = recursive_find(
                    body,
                    {
                        "fileurl",
                        "file_url",
                        "downloadurl",
                        "download_url",
                        "url",
                    },
                )
                if found_id:
                    result["file_entry_id"] = str(found_id)
                if found_url:
                    result["file_url"] = str(found_url)
                if result.get("file_url"):
                    break
        return result

    async def extract_metadata(
        self,
        file_entry_id: str,
        *,
        auto_match_album: bool = True,
    ) -> Any:
        return await self.request(
            "POST",
            f"/api/v1/tracks/{file_entry_id}/extract-metadata",
            json={"autoMatchAlbum": auto_match_album},
        )

    async def diagnose_upload(self, path: Path) -> dict[str, Any]:
        upload = await self.upload_file(path)
        discovery = await self.discover_file_entry(upload)
        metadata_probe: Any = None
        metadata_error: str | None = None
        file_id = discovery.get("file_entry_id")
        if file_id:
            try:
                metadata_probe = await self.extract_metadata(
                    str(file_id),
                    auto_match_album=True,
                )
            except Exception as exc:
                metadata_error = str(exc)
        return {
            "ok": bool(file_id),
            "file": str(path),
            "upload": upload.as_dict(),
            "discovery": discovery,
            "metadata": metadata_probe,
            "metadata_error": metadata_error,
            "hint": (
                None
                if discovery.get("file_url")
                else (
                    "If metadata works but file_url is empty, set "
                    "file_url_template in the connector settings after inspecting "
                    "the Traxx response or browser upload request."
                )
            ),
        }

    @staticmethod
    def extract_resource_id(metadata: Any, resource: str) -> int | None:
        if isinstance(metadata, dict):
            direct = get_case_insensitive(metadata, resource)
            if isinstance(direct, dict):
                value = get_case_insensitive(direct, "id")
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
            nested = get_case_insensitive(metadata, "metadata", "data")
            if nested is not metadata:
                return TraxxClient.extract_resource_id(nested, resource)
        return None

    async def create_track(self, payload: dict[str, Any]) -> Any:
        return await self.request("POST", "/api/v1/tracks", json=payload)

    @staticmethod
    def _resource_ids(value: Any, *keys: str) -> set[int]:
        output: set[int] = set()
        if isinstance(value, dict):
            for key in keys:
                nested = get_case_insensitive(value, key)
                if isinstance(nested, list):
                    for item in nested:
                        raw = get_case_insensitive(item, "id") if isinstance(item, dict) else item
                        with contextlib.suppress(TypeError, ValueError):
                            output.add(int(raw))
                elif isinstance(nested, dict):
                    raw = get_case_insensitive(nested, "id")
                    with contextlib.suppress(TypeError, ValueError):
                        output.add(int(raw))
                elif nested is not None:
                    with contextlib.suppress(TypeError, ValueError):
                        output.add(int(nested))
        return output

    @staticmethod
    def _imported_track_id(entry: Any) -> int | None:
        """Read a Traxx track id from both create and existing responses."""
        if not isinstance(entry, dict):
            return None
        track = entry.get("track")
        if isinstance(track, dict) and isinstance(track.get("track"), dict):
            track = track["track"]
        if not isinstance(track, dict):
            return None
        with contextlib.suppress(TypeError, ValueError):
            return int(track.get("id"))
        return None

    async def _find_existing_track(
        self, *, name: str, album_id: int, number: int
    ) -> dict[str, Any] | None:
        payload = await self.search_resource("tracks", name, limit=50)
        expected = normalize_text(name)
        for item in extract_items(payload):
            current = str(get_case_insensitive(item, "name", "title", default=""))
            if normalize_text(current) != expected:
                continue
            album_ids = self._resource_ids(item, "album_id", "albumId", "album")
            if album_ids and album_id not in album_ids:
                continue
            raw_number = get_case_insensitive(
                item, "number", "track_number", "trackNumber"
            )
            try:
                existing_number = int(str(raw_number).split("/", 1)[0])
            except (TypeError, ValueError):
                existing_number = 0
            if existing_number and existing_number != number:
                continue
            if not album_ids:
                # Without an album reference an identically named song is not a
                # safe deduplication match.
                continue
            return item
        return None

    async def _find_exact_resource(self, resource: str, name: str) -> int | None:
        expected = normalize_text(name)
        for item in await self.search_resource(resource, name, limit=50):
            current = str(get_case_insensitive(item, "name", "title", default=""))
            if normalize_text(current) != expected:
                continue
            value = get_case_insensitive(item, "id")
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return None

    async def ensure_artist(
        self,
        name: str,
        *,
        image: str = "",
        genres: list[str] | None = None,
    ) -> int:
        artist_id, _created = await self._ensure_artist_with_state(
            name, image=image, genres=genres
        )
        return artist_id

    async def _ensure_artist_with_state(
        self,
        name: str,
        *,
        image: str = "",
        genres: list[str] | None = None,
    ) -> tuple[int, bool]:
        """Return the artist id and whether this call created the entity."""
        existing = await self._find_exact_resource("artists", name)
        if existing:
            return existing, False
        created = await self.request(
            "POST",
            "/api/v1/artists",
            json={
                "name": name,
                "image_small": image or None,
                "genres": list(genres or []),
                "disabled": False,
            },
        )
        value = recursive_find(created, {"id"})
        if value is None:
            raise TraxxError(f"Traxx created artist {name!r} without returning an id")
        return int(value), True

    async def _find_existing_album(self, name: str, *, artist_id: int) -> int | None:
        """Find the exact artist/album pair without creating anything."""
        expected = normalize_text(name)
        for item in await self.search_resource("albums", name, limit=50):
            current = str(get_case_insensitive(item, "name", "title", default=""))
            if normalize_text(current) != expected:
                continue
            artist_ids = self._resource_ids(
                item, "artist_id", "artistId", "artists", "artist"
            )
            if not artist_ids or artist_id not in artist_ids:
                continue
            value = get_case_insensitive(item, "id")
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return None

    async def ensure_album(
        self,
        name: str,
        *,
        artist_id: int,
        release_date: str = "",
        image: str = "",
    ) -> int:
        existing = await self._find_existing_album(name, artist_id=artist_id)
        if existing:
            return existing
        return await self._create_album(
            name,
            artist_id=artist_id,
            release_date=release_date,
            image=image,
        )

    async def _create_album(
        self,
        name: str,
        *,
        artist_id: int,
        release_date: str = "",
        image: str = "",
    ) -> int:
        """Create an album and return the id produced by this exact request."""
        date_value = self._normalise_release_date(release_date)
        payload: dict[str, Any] = {
            "name": name,
            "image": image or None,
            "artists": [artist_id],
        }
        # Laravel's ``date`` validation accepts an absent optional field, but
        # rejects an explicitly supplied null value. Older connector versions
        # always sent null when Spotify only knew no date at all, which made an
        # otherwise valid album impossible to import.
        if date_value:
            payload["release_date"] = date_value
        created = await self.request(
            "POST",
            "/api/v1/albums",
            json=payload,
        )
        value = recursive_find(created, {"id"})
        if value is None:
            raise TraxxError(f"Traxx created album {name!r} without returning an id")
        return int(value)

    async def _delete_staging_file_entries(self, entry_ids: list[str]) -> bool:
        """Best-effort removal for uploads that were never attached to a track."""
        numeric_ids = sorted(
            {
                int(value)
                for value in entry_ids
                if str(value).strip().isdigit() and int(value) > 0
            }
        )
        if not numeric_ids:
            return not entry_ids
        try:
            result = await self.request(
                "POST",
                "/api/v1/file-entries/delete",
                json={"entryIds": numeric_ids, "deleteForever": True},
                allow_error=True,
            )
        except Exception:  # noqa: BLE001 - cleanup must not mask the root failure
            return False
        return 200 <= int(result.get("status") or 0) < 300

    @staticmethod
    def _normalise_release_date(value: str) -> str:
        """Return the most precise valid date Traxx can store.

        Spotify and file tags can legally contain only a year or year/month.
        Traxx expects a complete calendar date, so missing components use the
        first day rather than turning a useful import into a validation error.
        """
        candidate = str(value or "").strip()
        for pattern, suffix, date_format in (
            (r"\d{4}-\d{2}-\d{2}", "", "%Y-%m-%d"),
            (r"\d{4}-\d{2}", "-01", "%Y-%m-%d"),
            (r"\d{4}", "-01-01", "%Y-%m-%d"),
        ):
            if not re.fullmatch(pattern, candidate):
                continue
            complete = candidate + suffix
            try:
                datetime.strptime(complete, date_format)
            except ValueError:
                return ""
            return complete
        return ""

    async def inspect_album_import(
        self,
        album_id: int,
        *,
        expected_tracks: int = 1,
        track_hints: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Check both the size and catalogue identity of an imported album."""
        try:
            response = await self.request("GET", f"/api/v1/albums/{int(album_id)}")
        except TraxxError as exc:
            # The low-level request error has used both "returned 404" and
            # "failed (404)" over time. A missing resource is normal drift to
            # reconcile, not a connector outage, so recognise both forms.
            if re.search(r"(?:returned\s+404|failed\s+\(404\))", str(exc), re.IGNORECASE):
                return {
                    "album_id": int(album_id),
                    "exists": False,
                    "tracks_count": 0,
                    "expected_tracks": max(0, int(expected_tracks)),
                    "complete": False,
                }
            raise
        album = response.get("album", response) if isinstance(response, dict) else {}
        if not isinstance(album, dict):
            album = {}
        tracks = album.get("tracks")
        try:
            tracks_count = int(album.get("tracks_count") or 0)
        except (TypeError, ValueError):
            tracks_count = 0
        if not tracks_count and isinstance(tracks, list):
            tracks_count = len(tracks)
        expected = max(0, int(expected_tracks))
        catalog_verification: dict[str, Any] = {
            "checked": False,
            "complete": True,
            "expected_tracks": len(track_hints or []),
            "matched_tracks": 0,
            "missing": [],
            "reason": "",
        }
        if isinstance(tracks, list) and track_hints:
            remote_durations: dict[Path, int] = {}
            remote_titles: dict[Path, str] = {}
            for index, track in enumerate(tracks):
                if not isinstance(track, dict):
                    continue
                marker = Path(f"remote-{index}-{track.get('id') or index}")
                with contextlib.suppress(TypeError, ValueError):
                    remote_durations[marker] = int(track.get("duration") or 0)
                remote_durations.setdefault(marker, 0)
                remote_titles[marker] = str(track.get("name") or "")
            catalog_verification = verify_release_coverage(
                remote_durations,
                [TrackHint.from_mapping(item) for item in track_hints],
                observed_titles=remote_titles,
            )
            if catalog_verification.get("checked") and not catalog_verification.get(
                "complete"
            ):
                catalog_verification["reason"] = (
                    f"Only {catalog_verification.get('matched_tracks', 0)} of "
                    f"{catalog_verification.get('expected_tracks', 0)} catalogue "
                    "tracks are present in Traxx."
                )
        return {
            "album_id": int(album_id),
            "name": str(album.get("name") or ""),
            "exists": bool(album),
            "tracks_count": tracks_count,
            "expected_tracks": expected,
            "complete": (
                bool(album)
                and tracks_count >= expected
                and bool(catalog_verification.get("complete"))
            ),
            # Count equality is not identity proof.  Destructive retention in
            # Radar may only rely on a readback that matched the concrete
            # catalogue titles supplied for this release.
            "identity_verified": bool(track_hints)
            and bool(catalog_verification.get("checked"))
            and bool(catalog_verification.get("complete")),
            "catalog_verification": catalog_verification,
        }

    async def _load_cover(
        self,
        album_root: Path,
        cover_url: str,
        *,
        persist: bool = True,
    ) -> tuple[bytes | None, str, Path | None]:
        local = find_local_cover(album_root)
        if local:
            data = local.read_bytes()
            return data, cover_mime_type(local, data), local
        if cover_url:
            try:
                async with httpx.AsyncClient(
                    verify=self.config.verify_tls,
                    timeout=min(60, self.config.timeout_seconds),
                    follow_redirects=True,
                ) as client:
                    response = await client.get(cover_url)
                response.raise_for_status()
                if len(response.content) > 20 * 1024 * 1024:
                    raise TraxxError("Album cover exceeds 20 MiB")
                mime = response.headers.get("content-type", "").split(";", 1)[0]
                if not mime.startswith("image/"):
                    mime = cover_mime_type(None, response.content)
                suffix = ".png" if mime == "image/png" else ".jpg"
                saved = album_root / f"cover{suffix}"
                if persist:
                    saved.write_bytes(response.content)
                    return response.content, mime, saved
                return response.content, mime, None
            except Exception:
                pass
        return None, "image/jpeg", None

    async def _cover_url_for_traxx(
        self,
        *,
        external_url: str,
        local_cover: Path | None,
        staging_file_entry_ids: list[str] | None = None,
    ) -> str:
        if local_cover:
            try:
                upload = await self.upload_file(local_cover, upload_type="image")
                if upload.file_entry_id and staging_file_entry_ids is not None:
                    staging_file_entry_ids.append(str(upload.file_entry_id))
                discovery = await self.discover_file_entry(upload)
                discovered_id = discovery.get("file_entry_id")
                if (
                    discovered_id
                    and staging_file_entry_ids is not None
                    and str(discovered_id) not in staging_file_entry_ids
                ):
                    staging_file_entry_ids.append(str(discovered_id))
                uploaded = str(discovery.get("file_url") or "")
                if uploaded:
                    return uploaded
            except Exception:
                if not external_url:
                    raise
        return external_url

    def folder_fails_verification(
        self, folder: str | Path, track_hints: list[dict[str, Any]] | None
    ) -> bool:
        """Whether any file in the folder cannot be the track it stands for.

        Reads only local files, so it is cheap enough to run before trusting a
        recorded import. Only a positive finding counts: a folder that cannot
        be measured is not evidence of a wrong import, and discarding the
        record for it would re-upload every file this build cannot parse.
        """
        try:
            result = self.verify_album_folder(folder, track_hints)
            return bool(result.get("checked") and not result.get("complete"))
        except Exception:
            return False

    def verify_album_folder(
        self, folder: str | Path, track_hints: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        """Verify catalogue coverage without mutating tags or Traxx."""
        resolved = resolve_contained_path(self.downloads_dir, folder)
        files = sorted(
            path
            for path in resolved.rglob("*")
            if path.is_file() and path.suffix.casefold() in AUDIO_EXTENSIONS
        )
        if not files:
            return {
                "checked": False,
                "complete": True,
                "supported_files": 0,
                "expected_tracks": len(track_hints or []),
                "matched_tracks": 0,
                "missing": [],
                "reason": "No local audio files are available for source verification",
            }
        hints = [TrackHint.from_mapping(item) for item in (track_hints or [])]
        durations: dict[Path, int] = {}
        for path in files:
            with contextlib.suppress(Exception):
                durations[path] = inspect_audio_file(path).duration_ms
        # Unreadable files still participate by filename, with an unknown
        # duration that cannot falsely object to a valid match.
        for path in files:
            durations.setdefault(path, 0)
        coverage = verify_release_coverage(
            durations,
            hints,
            observed_titles={path: clean_title_from_filename(path) for path in files},
        )
        release = verify_release(durations, hints)
        reason = str(release.get("reason") or "")
        complete = bool(coverage.get("complete")) and not reason
        if not reason and coverage.get("checked") and not complete:
            reason = (
                f"Only {coverage.get('matched_tracks', 0)} of "
                f"{coverage.get('expected_tracks', 0)} catalogue tracks have "
                "a distinct matching local file."
            )
        return {
            **coverage,
            "complete": complete,
            "supported_files": len(files),
            "reason": reason,
        }

    async def import_album_folder(
        self,
        folder: str | Path,
        *,
        dry_run: bool,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        artist: str = "",
        album: str = "",
        release_date: str = "",
        cover_url: str = "",
        genres: list[str] | None = None,
        track_hints: list[dict[str, Any]] | None = None,
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        key = idempotency_key.strip()
        if len(key) > 256 or "\x00" in key:
            raise ValueError("Invalid import idempotency key")
        if dry_run or not key or self.import_ledger is None:
            return await self._import_album_folder_once(
                folder,
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
            )

        ledger = self.import_ledger.read()
        previous = ledger.get(key)
        if isinstance(previous, dict) and previous.get("status") == "completed":
            result = previous.get("result")
            # A recorded success certifies that this folder was imported. It
            # cannot certify that the import was right: entries written before
            # the files were checked against the release listing keep
            # reporting success for a wrong recording, and no retry can ever
            # correct it. Re-checking is local and cheap, so the ledger only
            # answers for a folder that would still pass today.
            if isinstance(result, dict) and not self.folder_fails_verification(
                folder, track_hints
            ):
                album_id = int(result.get("album_id") or 0)
                expected_tracks = int(
                    result.get("expected_track_count")
                    or result.get("unique_track_count")
                    or result.get("imported_count")
                    or 0
                )
                if album_id and expected_tracks:
                    current = await self.inspect_album_import(
                        album_id, expected_tracks=expected_tracks
                    )
                    if current["complete"]:
                        return {**result, "idempotent": True, "verification": current}

        ledger[key] = {
            "status": "processing",
            "folder": str(folder),
            "updated_at": datetime.now(UTC).isoformat(),
        }
        self.import_ledger.write(ledger)
        try:
            result = await self._import_album_folder_once(
                folder,
                dry_run=False,
                rights_confirmed=rights_confirmed,
                rights_basis=rights_basis,
                rights_reference=rights_reference,
                artist=artist,
                album=album,
                release_date=release_date,
                cover_url=cover_url,
                genres=genres,
                track_hints=track_hints,
            )
        except Exception as exc:
            ledger = self.import_ledger.read()
            ledger[key] = {
                "status": "failed",
                "folder": str(folder),
                "error": str(exc),
                "updated_at": datetime.now(UTC).isoformat(),
            }
            self.import_ledger.write(ledger)
            raise
        marker = result.get("complete")
        complete = (
            bool(marker)
            if marker is not None
            else int(result.get("unresolved_count") or 0) == 0
            and int(result.get("imported_count") or 0) > 0
        )
        ledger = self.import_ledger.read()
        ledger[key] = {
            "status": "completed" if complete else "needs_configuration",
            "folder": str(folder),
            "result": result,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        self.import_ledger.write(ledger)
        return {**result, "idempotent": False}

    async def _import_album_folder_once(
        self,
        folder: str | Path,
        *,
        dry_run: bool,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
        artist: str = "",
        album: str = "",
        release_date: str = "",
        cover_url: str = "",
        genres: list[str] | None = None,
        track_hints: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        resolved = resolve_contained_path(self.downloads_dir, folder)
        if not resolved.is_dir():
            raise FileNotFoundError(resolved)
        # A remote cover becomes part of the artifact before the authoritative
        # scan. Previously it was downloaded afterwards and could bypass the
        # malware gate entirely.
        cover_data, cover_mime, cover_path = await self._load_cover(
            resolved, cover_url, persist=not dry_run
        )
        malware_scan: dict[str, Any] = {
            "enabled": False,
            "clean": None,
            "scanned_files": 0,
            "findings": [],
            "quarantined": False,
        }
        if self.malware_scanner is not None:
            malware_scan = await self.malware_scanner.scan_folder(
                resolved, quarantine_on_detection=True
            )
            if not malware_scan.get("clean"):
                finding = (malware_scan.get("findings") or [{}])[0]
                raise MalwareDetectedError(
                    "[MALWARE_DETECTED] Import blocked; artifact quarantined. "
                    f"Signature: {finding.get('signature') or 'unknown'}"
                )
        files = sorted(
            path
            for path in resolved.rglob("*")
            if path.is_file() and path.suffix.casefold() in AUDIO_EXTENSIONS
        )
        if not files:
            raise TraxxError(f"No supported audio files found in {resolved}")

        first_local = inspect_audio_file(files[0])
        expected_artist = artist.strip() or first_local.artist
        expected_album = album.strip() or first_local.album or resolved.name
        # Prefer the catalogue value, but keep a valid date already embedded
        # in the files when the recommendation source did not provide one.
        # Besides avoiding validation failures, this keeps the album eligible
        # for Traxx's date-based "new releases" channels.
        release_date = self._normalise_release_date(
            release_date
        ) or self._normalise_release_date(first_local.release_date)
        inspection = [
            {"path": str(path), "metadata": inspect_audio_file(path).as_dict()}
            for path in files
        ]
        if dry_run:
            return {
                "dry_run": True,
                "folder": str(resolved),
                "track_count": len(files),
                "rights": rights.as_dict(),
                "malware_scan": malware_scan,
                "expected": {
                    "artist": expected_artist,
                    "album": expected_album,
                    "release_date": release_date,
                    "cover": str(cover_path) if cover_path else cover_url,
                },
                "tracks": inspection,
            }

        parsed_track_hints = [
            TrackHint.from_mapping(item) for item in (track_hints or [])
        ]
        # Decided for the whole folder at once: only there can it be seen that
        # two files claimed the same entry of the release listing.
        assigned = assign_track_hints(
            files, album_root=resolved, hints=parsed_track_hints
        )
        durations = {path: inspect_audio_file(path).duration_ms for path in files}
        source_verification = verify_release_coverage(
            durations,
            parsed_track_hints,
            observed_titles={path: clean_title_from_filename(path) for path in files},
        )
        if source_verification.get("checked") and not source_verification.get(
            "complete"
        ):
            missing = ", ".join(
                str(item.get("title") or "")
                for item in source_verification.get("missing", [])[:5]
            )
            raise TraxxError(
                f"Only {source_verification.get('matched_tracks', 0)} of "
                f"{source_verification.get('expected_tracks', 0)} catalogue "
                "tracks have a distinct matching local file; Traxx was not "
                f"changed. Missing: {missing or 'unknown tracks'}"
            )
        # Whether this folder can be the release at all. Judged before the
        # per-file check, because a file that matched nothing passes that one
        # untouched — and an unrelated folder consists of exactly those.
        release = verify_release(durations, parsed_track_hints)
        if release["reason"]:
            raise TraxxError(release["reason"])
        # Checked before any tag is written: ensure_audio_metadata stamps the
        # expected title onto the file, so a wrong file that gets past here is
        # published under the right name and can no longer be told apart.
        rejected = verify_assignment(
            assigned,
            durations,
            # The filename, not the tag: a previous run of this importer
            # writes the expected title into the file, so the tag agrees with
            # the listing even when the audio does not. The name a stranger
            # gave the file is the only part it cannot have rewritten.
            observed_titles={path: clean_title_from_filename(path) for path in files},
        )
        files = [path for path in files if path not in rejected]
        if not files:
            reasons = "; ".join(dict.fromkeys(rejected.values()))
            raise TraxxError(
                "No verified audio files remain; Traxx was not changed. "
                f"{reasons[:900]}"
            )
        tag_results: list[dict[str, Any]] = []
        for path in files:
            tag_results.append(
                ensure_audio_metadata(
                    path,
                    album_root=resolved,
                    artist=expected_artist,
                    album=expected_album,
                    release_date=release_date,
                    genres=list(genres or []),
                    track_hints=track_hints,
                    cover_data=cover_data,
                    cover_mime=cover_mime,
                    hint=assigned.get(path),
                ).as_dict()
            )

        # Asked before anything is created in the library. Without it the
        # importer created the artist and the album, then failed on every
        # track, and left an empty album behind — nineteen of them on the live
        # instance before this was found.
        oversized = await self.check_upload_sizes(files)
        if oversized:
            raise TraxxError(oversized)

        # Complete the fallible upload/FileEntry/metadata phase before creating
        # a library artist or album. A failed upload used to happen after
        # ensure_album(), leaving the empty albums seen in production.
        existing_artist_id = await self._find_exact_resource("artists", expected_artist)
        existing_album_id = (
            await self._find_existing_album(
                expected_album, artist_id=existing_artist_id
            )
            if existing_artist_id
            else None
        )
        existing_tracks: dict[Path, dict[str, Any]] = {}
        if existing_album_id:
            for path in files:
                local = inspect_audio_file(path)
                existing = await self._find_existing_track(
                    name=local.title,
                    album_id=existing_album_id,
                    number=max(1, local.track_number),
                )
                if existing is not None:
                    existing_tracks[path] = existing
        files_to_upload = [path for path in files if path not in existing_tracks]
        cover_file_entry_ids: list[str] = []
        audio_file_entry_ids: dict[Path, list[str]] = {
            path: [] for path in files_to_upload
        }
        # A completed idempotent readback has nothing new to attach the image
        # to.  Uploading the same cover again on every reconcile leaked one
        # FileEntry per run even though no catalogue entity changed.
        if files_to_upload or not existing_album_id:
            try:
                traxx_cover_url = await self._cover_url_for_traxx(
                    external_url=cover_url,
                    local_cover=cover_path,
                    staging_file_entry_ids=cover_file_entry_ids,
                )
            except Exception:
                # No library mutation has started, so every FileEntry produced
                # by the failed cover upload is unreferenced.
                await self._delete_staging_file_entries(cover_file_entry_ids)
                raise
        else:
            traxx_cover_url = ""
        # If local cover upload fell back to the external URL, its FileEntry is
        # not the URL any entity will receive and is safe to remove immediately.
        cover_upload_selected = bool(
            cover_file_entry_ids
            and traxx_cover_url
            and traxx_cover_url != str(cover_url or "")
        )
        if cover_file_entry_ids and not cover_upload_selected:
            await self._delete_staging_file_entries(cover_file_entry_ids)
            cover_file_entry_ids.clear()
        cover_report = describe_cover(cover_path, traxx_cover_url)
        prepared: dict[Path, dict[str, Any]] = {}
        preflight_failures: list[str] = []
        for path in files_to_upload:
            try:
                upload = await self.upload_file(path)
                if upload.file_entry_id:
                    audio_file_entry_ids[path].append(str(upload.file_entry_id))
                discovery = await self.discover_file_entry(upload)
                file_id = discovery.get("file_entry_id")
                file_url = discovery.get("file_url")
                if file_id and str(file_id) not in audio_file_entry_ids[path]:
                    audio_file_entry_ids[path].append(str(file_id))
                if not file_id:
                    preflight_failures.append(
                        f"{path.name}: no BeMusic FileEntry id was exposed"
                    )
                    continue
                extracted = await self.extract_metadata(
                    str(file_id), auto_match_album=False
                )
                metadata = (
                    get_case_insensitive(extracted, "metadata", default=extracted)
                    if isinstance(extracted, dict)
                    else {}
                )
                if not file_url:
                    preflight_failures.append(
                        f"{path.name}: a playable uploaded-file URL is required"
                    )
                    continue
                prepared[path] = {
                    "upload": upload,
                    "discovery": discovery,
                    "file_id": file_id,
                    "file_url": file_url,
                    "metadata": metadata,
                }
            except Exception as exc:  # noqa: BLE001
                preflight_failures.append(f"{path.name}: {exc}")
        if preflight_failures or len(prepared) != len(files_to_upload):
            staging_removed = await self._delete_staging_file_entries(
                cover_file_entry_ids
                + [
                    entry_id
                    for values in audio_file_entry_ids.values()
                    for entry_id in values
                ]
            )
            cleanup_note = (
                " Uploaded staging FileEntries were removed."
                if staging_removed
                else " Uploaded staging FileEntries require the Traxx temporary-file cleanup policy."
            )
            raise TraxxError(
                "All audio uploads must expose a FileEntry id and playable URL "
                "before Traxx creates the album; no artist, album or track was "
                "created."
                + cleanup_note
                + " "
                + "; ".join(preflight_failures[:5])
            )

        artist_created = False
        entity_stage = ""
        try:
            if existing_artist_id:
                artist_id = existing_artist_id
            else:
                entity_stage = "artist"
                artist_id, artist_created = await self._ensure_artist_with_state(
                    expected_artist,
                    image=traxx_cover_url,
                    genres=list(genres or []),
                )
            if existing_album_id:
                album_id = existing_album_id
                album_created = False
            else:
                # Do not call ensure_album() here: its second lookup could adopt an
                # album created by another request between preflight and mutation,
                # after which an empty-import rollback would not own its target.
                entity_stage = "album"
                album_id = await self._create_album(
                    expected_album,
                    artist_id=artist_id,
                    release_date=release_date,
                    image=traxx_cover_url,
                )
                album_created = True
        except Exception as exc:
            # Audio uploads cannot be attached before an album id exists.  The
            # cover is retained only when a successful artist creation or an
            # ambiguous artist/album mutation may have attached it. A structured
            # 4xx rejection (or a read-only lookup failure) proves that this
            # request did not create a new cover reference.
            await self._delete_staging_file_entries(
                [
                    entry_id
                    for values in audio_file_entry_ids.values()
                    for entry_id in values
                ]
            )
            mutation_may_have_committed = not (
                isinstance(exc, TraxxError)
                and (
                    exc.definitively_rejected
                    or exc.method in {"GET", "HEAD", "OPTIONS"}
                )
            )
            cover_may_be_referenced = bool(
                artist_created
                or (
                    entity_stage in {"artist", "album"}
                    and mutation_may_have_committed
                )
            )
            if cover_upload_selected and not cover_may_be_referenced:
                await self._delete_staging_file_entries(cover_file_entry_ids)
            raise

        cover_referenced_by_artist = bool(cover_upload_selected and artist_created)
        cover_referenced_by_album = bool(cover_upload_selected and album_created)
        cover_may_be_referenced_by_track = False
        imported: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = [
            {"path": str(path), "stage": "verification", "reason": reason}
            for path, reason in rejected.items()
        ]
        for file_index, path in enumerate(files):
            local = inspect_audio_file(path)
            attempted_title = local.title
            attempted_number = max(1, local.track_number)
            create_attempted = False
            try:
                hint = assigned.get(path)
                track_artist_names = list(hint.artists) if hint and hint.artists else []
                if not track_artist_names and hint and hint.artist:
                    track_artist_names = [hint.artist]
                if not track_artist_names:
                    track_artist_names = [local.artist or expected_artist]
                normalized_names: set[str] = set()
                track_artist_ids: list[int] = []
                for name in track_artist_names:
                    normalized = normalize_text(name)
                    if not normalized or normalized in normalized_names:
                        continue
                    normalized_names.add(normalized)
                    if normalized == normalize_text(expected_artist):
                        current_artist_id = artist_id
                    else:
                        current_artist_id = await self.ensure_artist(
                            name,
                            genres=local.genres or list(genres or []),
                        )
                    track_artist_ids.append(current_artist_id)
                if not track_artist_ids:
                    track_artist_ids = [artist_id]
                existing_track = existing_tracks.get(path)
                if existing_track is None:
                    existing_track = await self._find_existing_track(
                        name=local.title,
                        album_id=album_id,
                        number=max(1, local.track_number),
                    )
                if existing_track is not None:
                    # A concurrent importer can win between preflight and this
                    # second lookup. Its track owns a different file, so ours
                    # is still staging and can be removed safely.
                    await self._delete_staging_file_entries(
                        audio_file_entry_ids.get(path, [])
                    )
                    imported.append(
                        {
                            "path": str(path),
                            "existing": True,
                            "track": existing_track,
                            "metadata": local.as_dict(),
                        }
                    )
                    continue
                ready = prepared[path]
                upload = ready["upload"]
                discovery = ready["discovery"]
                file_id = ready["file_id"]
                file_url = ready["file_url"]
                metadata = ready["metadata"]
                duration = int(
                    get_case_insensitive(
                        metadata,
                        "duration",
                        default=local.duration_ms,
                    )
                    or local.duration_ms
                )
                title = str(
                    get_case_insensitive(
                        metadata,
                        "title",
                        "name",
                        default=local.title,
                    )
                    or local.title
                )
                number_raw = get_case_insensitive(
                    metadata,
                    "track_number",
                    "tracknumber",
                    "number",
                    default=local.track_number,
                )
                try:
                    number = int(str(number_raw).split("/", 1)[0])
                except (TypeError, ValueError):
                    number = local.track_number
                attempted_title = title
                attempted_number = max(1, number)
                payload: dict[str, Any] = {
                    "name": attempted_title,
                    "duration": max(1, duration),
                    "number": attempted_number,
                    "artists": track_artist_ids,
                    "album_id": album_id,
                    "src": file_url,
                    "genres": normalize_genres(
                        get_case_insensitive(metadata, "genres"),
                        fallback=local.genres or list(genres or []),
                    ),
                }
                if traxx_cover_url:
                    payload["image"] = traxx_cover_url
                create_attempted = True
                created = await self.create_track(payload)
                if cover_upload_selected:
                    cover_may_be_referenced_by_track = True
                imported.append(
                    {
                        "path": str(path),
                        "file_entry_id": file_id,
                        "track": created,
                        "metadata": local.as_dict(),
                    }
                )
            except Exception as exc:
                cleanup_note = ""
                definitely_rejected = bool(
                    create_attempted
                    and isinstance(exc, TraxxError)
                    and exc.definitively_rejected
                )
                mutation_ambiguous = create_attempted and not definitely_rejected
                if mutation_ambiguous and cover_upload_selected:
                    # The response may have been lost after commit. Both audio
                    # and cover can now be referenced by the unseen track.
                    cover_may_be_referenced_by_track = True
                # Re-read with exactly the identity sent to Traxx. This can
                # recover a lost success response, but a negative search alone
                # never proves that an ambiguous POST did not commit.
                proven_existing: dict[str, Any] | None = None
                with contextlib.suppress(Exception):
                    proven_existing = await self._find_existing_track(
                        name=attempted_title,
                        album_id=album_id,
                        number=attempted_number,
                    )
                if proven_existing is not None:
                    if not create_attempted or definitely_rejected:
                        # The found track belongs to another request; our POST
                        # never ran or was positively rejected.
                        await self._delete_staging_file_entries(
                            audio_file_entry_ids.get(path, [])
                        )
                    imported.append(
                        {
                            "path": str(path),
                            "existing": True,
                            "track": proven_existing,
                            "metadata": local.as_dict(),
                        }
                    )
                    continue
                if (
                    (not create_attempted or definitely_rejected)
                    and audio_file_entry_ids.get(path)
                ):
                    removed_staging = await self._delete_staging_file_entries(
                        audio_file_entry_ids[path]
                    )
                    cleanup_note = (
                        " Staging-Upload entfernt."
                        if removed_staging
                        else " Staging-Upload konnte nicht entfernt werden."
                    )
                unresolved.append(
                    {
                        "path": str(path),
                        "stage": "exception",
                        "reason": str(exc) + cleanup_note,
                    }
                )
                if "may not be greater than" in str(exc):
                    # A size limit applies to every file of this album, so
                    # trying the rest only repeats the same refusal and keeps
                    # the instance busy for nothing. Every later file was only
                    # preflight-uploaded and is therefore safe to remove.
                    await self._delete_staging_file_entries(
                        [
                            entry_id
                            for remaining in files[file_index + 1 :]
                            for entry_id in audio_file_entry_ids.get(remaining, [])
                        ]
                    )
                    unresolved.append(
                        {
                            "path": str(resolved),
                            "stage": "abgebrochen",
                            "reason": (
                                "Weitere Dateien nicht versucht: die Instanz "
                                "lehnt sie wegen ihrer Grösse ab."
                            ),
                        }
                    )
                    break
        unique_track_ids = {
            track_id
            for entry in imported
            if (track_id := self._imported_track_id(entry)) is not None
        }
        if album_created and not unique_track_ids:
            # The only album we may remove is the one this exact call created,
            # and only after a fresh read proves it still has zero tracks. This
            # closes the final all-create_track-failed empty-album path without
            # ever touching an existing or concurrently populated album.
            snapshot = await self.inspect_album_import(
                album_id, expected_tracks=0, track_hints=[]
            )
            if int(snapshot.get("tracks_count") or 0) == 0:
                rollback = await self.request(
                    "DELETE", f"/api/v1/albums/{album_id}", allow_error=True
                )
                rollback_status = int(rollback.get("status") or 0)
                reasons = "; ".join(
                    str(item.get("reason") or "") for item in unresolved[:5]
                )
                if 200 <= rollback_status < 300:
                    cover_referenced_by_album = False
                    if not (
                        cover_referenced_by_artist
                        or cover_may_be_referenced_by_track
                    ):
                        await self._delete_staging_file_entries(cover_file_entry_ids)
                    raise TraxxError(
                        "Traxx rejected every prepared track; the newly created "
                        f"empty album was rolled back. {reasons}".strip()
                    )
                raise TraxxError(
                    "Traxx rejected every prepared track and rollback of the empty "
                    f"album failed ({rollback_status}). {reasons}".strip()
                )
        if not (
            cover_referenced_by_artist
            or cover_referenced_by_album
            or cover_may_be_referenced_by_track
        ):
            await self._delete_staging_file_entries(cover_file_entry_ids)
        expected_track_count = int(
            source_verification.get("expected_tracks")
            or len(unique_track_ids)
            or len(imported)
        )
        try:
            verification = await self.inspect_album_import(
                album_id,
                expected_tracks=expected_track_count,
                track_hints=track_hints,
            )
        except Exception as exc:  # noqa: BLE001
            # The mutation response is not independent proof.  Preserve it
            # for diagnosis but keep ``complete`` false until a later checker
            # can read the album back successfully.
            verification = {
                "album_id": album_id,
                "expected_tracks": expected_track_count,
                "complete": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        complete = bool(verification.get("complete")) and bool(
            source_verification.get("complete", True)
        )
        return {
            "dry_run": False,
            "folder": str(resolved),
            "track_count": len(files),
            "imported_count": len(imported),
            "unique_track_count": len(unique_track_ids),
            "expected_track_count": expected_track_count,
            "unresolved_count": len(unresolved),
            "complete": complete,
            "source_verification": source_verification,
            "verification": verification,
            "rights": rights.as_dict(),
            "malware_scan": malware_scan,
            "artist_id": artist_id,
            "album_id": album_id,
            "cover_url": traxx_cover_url,
            "cover": cover_report,
            "tag_results": tag_results,
            "imported": imported,
            "unresolved": unresolved,
        }

    async def import_metadata(
        self,
        *,
        model_type: str,
        provider: str,
        external_id: str,
        import_similar_artists: bool = False,
        import_albums: bool = False,
        import_lyrics: bool = False,
    ) -> Any:
        payload = {
            "modelType": model_type,
            "metadataProvider": provider,
            "importSimilarArtists": import_similar_artists,
            "importAlbums": import_albums,
            "importLyrics": import_lyrics,
        }
        payload["spotifyId" if provider == "spotify" else "deezerId"] = external_id
        return await self.request(
            "POST",
            "/api/v1/import-media/single-item",
            json=payload,
        )

    async def create_playlist(
        self,
        *,
        name: str,
        description: str = "",
        public: bool = False,
        user_id: str = "",
    ) -> Any:
        target = target_user_id(user_id)
        path = (
            f"/api/v1/users/{target}/managed-playlists"
            if target
            else "/api/v1/playlists"
        )
        return await self.request(
            "POST",
            path,
            json={"name": name, "description": description, "public": public},
        )

    async def add_playlist_tracks(
        self,
        *,
        playlist_id: int,
        track_ids: list[int],
    ) -> Any:
        return await self.request(
            "POST",
            f"/api/v1/playlists/{playlist_id}/tracks/add",
            json={"ids": track_ids},
        )

    async def remove_playlist_tracks(
        self,
        *,
        playlist_id: int,
        track_ids: list[int],
    ) -> Any:
        return await self.request(
            "POST",
            f"/api/v1/playlists/{playlist_id}/tracks/remove",
            json={"ids": track_ids},
        )

    async def list_playlists(
        self, *, page: int = 1, per_page: int = 20, user_id: str = ""
    ) -> Any:
        """List service/actor playlists or a target member's playlists."""
        who = target_user_id(user_id) or "me"
        return await self.request(
            "GET",
            f"/api/v1/users/{who}/playlists",
            params={"page": page, "perPage": per_page},
        )

    async def get_playlist(self, playlist_id: int) -> Any:
        """Return playlist details including its tracks.

        BeMusic answers GET /api/v1/playlists/{id} with the playlist model; the
        track listing lives on the paginated /playlists/{id}/tracks subresource,
        so both are combined here. The subresource is probed tolerantly because
        an installation may already inline tracks in the playlist payload.
        """
        payload = await self.request("GET", f"/api/v1/playlists/{playlist_id}")
        result: dict[str, Any] = payload if isinstance(payload, dict) else {"playlist": payload}
        tracks = self._playlist_track_items(payload)
        if not tracks:
            probe = await self.request(
                "GET",
                f"/api/v1/playlists/{playlist_id}/tracks",
                params={"page": 1, "perPage": 500},
                allow_error=True,
            )
            if int(probe.get("status") or 0) < 400:
                tracks = self._playlist_track_items(probe.get("body"))
        result = dict(result)
        result["tracks"] = tracks
        return result

    @staticmethod
    def _playlist_track_items(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            tracks = get_case_insensitive(payload, "tracks")
            if isinstance(tracks, list):
                return [item for item in tracks if isinstance(item, dict)]
            if isinstance(tracks, dict):
                return extract_items(tracks)
        return extract_items(payload)

    async def playlist_track_ids(self, playlist_id: int) -> list[int]:
        payload = await self.get_playlist(playlist_id)
        ids: list[int] = []
        for item in self._playlist_track_items(payload):
            raw = get_case_insensitive(item, "id")
            with contextlib.suppress(TypeError, ValueError):
                value = int(raw)
                if value not in ids:
                    ids.append(value)
        return ids

    async def update_playlist(
        self,
        *,
        playlist_id: int,
        name: str = "",
        description: str = "",
        public: bool | None = None,
    ) -> Any:
        """Partially update a playlist; only supplied fields are sent."""
        payload: dict[str, Any] = {}
        if name:
            payload["name"] = name
        if description:
            payload["description"] = description
        if public is not None:
            payload["public"] = public
        if not payload:
            raise TraxxError(
                "update_playlist needs at least one of name, description or public"
            )
        return await self.request(
            "PUT",
            f"/api/v1/playlists/{playlist_id}",
            json=payload,
        )

    async def replace_playlist_tracks(
        self,
        *,
        playlist_id: int,
        track_ids: list[int],
    ) -> dict[str, Any]:
        """Make the playlist contain exactly ``track_ids``.

        Implemented client-side as read + remove + add because the API offers
        no atomic replace. Removing nothing and adding nothing are both no-ops,
        so the call is idempotent and safe on an empty playlist.
        """
        current = await self.playlist_track_ids(playlist_id)
        if current:
            await self.remove_playlist_tracks(
                playlist_id=playlist_id, track_ids=current
            )
        if track_ids:
            await self.add_playlist_tracks(
                playlist_id=playlist_id, track_ids=track_ids
            )
        return {
            "playlist_id": playlist_id,
            "removed_track_ids": current,
            "added_track_ids": list(track_ids),
        }
