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
)
from .tus import TusUnsupported, TusUploader, TusUploadResult, recursive_find


class TraxxError(RuntimeError):
    pass


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


class TraxxClient:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        downloads_dir: Path,
        import_ledger: AtomicJsonStore | None = None,
        actor_token: str = "",
    ):
        self.config = config
        self.downloads_dir = downloads_dir
        self.import_ledger = import_ledger
        # An actor token replaces only the Authorization bearer, so requests
        # run as a specific Traxx user while base_url, TLS verification,
        # proxy headers and timeouts stay those of the shared configuration.
        self.actor_token = actor_token
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
        async with httpx.AsyncClient(
            base_url=self.config.base_url,
            headers=self.headers,
            verify=self.config.verify_tls,
            timeout=self.config.timeout_seconds,
            follow_redirects=True,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
        if response.status_code >= 400 and not allow_error:
            raise TraxxError(
                f"Traxx {method} {path} failed ({response.status_code}): "
                f"{response.text[:1400]}"
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
        who = str(user_id).strip() or "me"
        if who != "me" and not who.isdigit():
            raise TraxxError(f"Not a Traxx user id: {user_id!r}")
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
        existing = await self._find_exact_resource("artists", name)
        if existing:
            return existing
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
        return int(value)

    async def ensure_album(
        self,
        name: str,
        *,
        artist_id: int,
        release_date: str = "",
        image: str = "",
    ) -> int:
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
        date_value = release_date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", release_date) else ""
        if not date_value and re.fullmatch(r"\d{4}", release_date):
            date_value = f"{release_date}-01-01"
        created = await self.request(
            "POST",
            "/api/v1/albums",
            json={
                "name": name,
                "release_date": date_value or None,
                "image": image or None,
                "artists": [artist_id],
            },
        )
        value = recursive_find(created, {"id"})
        if value is None:
            raise TraxxError(f"Traxx created album {name!r} without returning an id")
        return int(value)

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
    ) -> str:
        if local_cover:
            try:
                upload = await self.upload_file(local_cover, upload_type="image")
                discovery = await self.discover_file_entry(upload)
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
            resolved = resolve_contained_path(self.downloads_dir, folder)
            files = sorted(
                path
                for path in resolved.rglob("*")
                if path.is_file() and path.suffix.casefold() in AUDIO_EXTENSIONS
            )
            if not files:
                return False
            assigned = assign_track_hints(
                files,
                album_root=resolved,
                hints=[TrackHint.from_mapping(item) for item in (track_hints or [])],
            )
            durations: dict[Path, int] = {}
            for path in files:
                # Per file, so one unreadable track cannot blind the check for
                # the rest of the folder. A missing length simply leaves the
                # name as the only signal for that file.
                with contextlib.suppress(Exception):
                    durations[path] = inspect_audio_file(path).duration_ms
            return bool(
                verify_assignment(
                    assigned,
                    durations,
                    observed_titles={
                        path: clean_title_from_filename(path) for path in files
                    },
                )
            )
        except Exception:
            return False

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
                return {**result, "idempotent": True}

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
        unresolved_count = int(result.get("unresolved_count") or 0)
        ledger = self.import_ledger.read()
        ledger[key] = {
            "status": "needs_configuration" if unresolved_count else "completed",
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
        cover_data, cover_mime, cover_path = await self._load_cover(
            resolved, cover_url, persist=not dry_run
        )
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
        traxx_cover_url = await self._cover_url_for_traxx(
            external_url=cover_url,
            local_cover=cover_path,
        )
        cover_report = describe_cover(cover_path, traxx_cover_url)
        artist_id = await self.ensure_artist(
            expected_artist,
            image=traxx_cover_url,
            genres=list(genres or []),
        )
        album_id = await self.ensure_album(
            expected_album,
            artist_id=artist_id,
            release_date=release_date,
            image=traxx_cover_url,
        )

        imported: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = [
            {"path": str(path), "stage": "verification", "reason": reason}
            for path, reason in rejected.items()
        ]
        for path in files:
            local = inspect_audio_file(path)
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
                existing_track = await self._find_existing_track(
                    name=local.title,
                    album_id=album_id,
                    number=max(1, local.track_number),
                )
                if existing_track is not None:
                    imported.append(
                        {
                            "path": str(path),
                            "existing": True,
                            "track": existing_track,
                            "metadata": local.as_dict(),
                        }
                    )
                    continue
                upload = await self.upload_file(path)
                discovery = await self.discover_file_entry(upload)
                file_id = discovery.get("file_entry_id")
                file_url = discovery.get("file_url")
                if not file_id:
                    unresolved.append(
                        {
                            "path": str(path),
                            "stage": "upload",
                            "reason": "No BeMusic FileEntry id was exposed",
                            "upload": upload.as_dict(),
                            "discovery": discovery,
                        }
                    )
                    continue
                extracted = await self.extract_metadata(
                    str(file_id),
                    # The importer already resolved the authoritative album
                    # above and passes its id explicitly when creating the
                    # track. Letting BeMusic auto-match here can create a
                    # second, empty album from a featured track artist before
                    # the real track is saved (for example an album by George
                    # Fitzgerald with one Bonobo feature).
                    auto_match_album=False,
                )
                metadata = (
                    get_case_insensitive(extracted, "metadata", default=extracted)
                    if isinstance(extracted, dict)
                    else {}
                )
                if not file_url:
                    unresolved.append(
                        {
                            "path": str(path),
                            "stage": "track-create",
                            "reason": "A playable uploaded-file URL is required",
                            "upload": upload.as_dict(),
                            "discovery": discovery,
                            "metadata": metadata,
                        }
                    )
                    continue
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
                payload: dict[str, Any] = {
                    "name": title,
                    "duration": max(1, duration),
                    "number": max(1, number),
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
                created = await self.create_track(payload)
                imported.append(
                    {
                        "path": str(path),
                        "file_entry_id": file_id,
                        "track": created,
                        "metadata": local.as_dict(),
                    }
                )
            except Exception as exc:
                unresolved.append(
                    {
                        "path": str(path),
                        "stage": "exception",
                        "reason": str(exc),
                    }
                )
                if "may not be greater than" in str(exc):
                    # A size limit applies to every file of this album, so
                    # trying the rest only repeats the same refusal and keeps
                    # the instance busy for nothing.
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
        return {
            "dry_run": False,
            "folder": str(resolved),
            "track_count": len(files),
            "imported_count": len(imported),
            "unresolved_count": len(unresolved),
            "rights": rights.as_dict(),
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
    ) -> Any:
        return await self.request(
            "POST",
            "/api/v1/playlists",
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

    async def list_playlists(self, *, page: int = 1, per_page: int = 20) -> Any:
        """List the playlists of the acting user (service account or actor)."""
        return await self.request(
            "GET",
            "/api/v1/users/me/playlists",
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
