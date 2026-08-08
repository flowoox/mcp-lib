from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import normalize_text, resolve_contained_path
from mcp_common.rights import validate_rights
from mcp_common.store import AtomicJsonStore

from .config import RuntimeConfig
from .metadata import (
    AUDIO_EXTENSIONS,
    TrackHint,
    choose_track_hint,
    cover_mime_type,
    ensure_audio_metadata,
    find_local_cover,
    inspect_audio_file,
)
from .tus import TusUploader, TusUploadResult, recursive_find


class TraxxError(RuntimeError):
    pass


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


class TraxxClient:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        downloads_dir: Path,
        import_ledger: AtomicJsonStore | None = None,
    ):
        self.config = config
        self.downloads_dir = downloads_dir
        self.import_ledger = import_ledger

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
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
        payload = await self.request("GET", "/api/v1/tracks", params={"perPage": 1})
        return {
            "ok": True,
            "base_url": self.config.base_url,
            "api": "/api/v1/tracks",
            "response_type": type(payload).__name__,
        }

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

    async def upload_file(
        self,
        path: Path,
        *,
        upload_type: str = "track",
    ) -> TusUploadResult:
        endpoint = urljoin(
            f"{self.config.base_url}/",
            self.config.tus_endpoint.lstrip("/"),
        )
        uploader = TusUploader(
            endpoint=endpoint,
            headers=self.headers,
            verify_tls=self.config.verify_tls,
            chunk_size=self.config.upload_chunk_size,
            timeout=max(300, self.config.timeout_seconds),
        )
        return await uploader.upload(path, upload_type=upload_type)

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
        if not upload.file_entry_id:
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
        payload = await self.list_resource("tracks", page=1, per_page=100, query=name)
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
        payload = await self.list_resource(resource, page=1, per_page=50, query=name)
        expected = normalize_text(name)
        for item in extract_items(payload):
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
        payload = await self.list_resource("albums", page=1, per_page=50, query=name)
        expected = normalize_text(name)
        for item in extract_items(payload):
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
            if isinstance(result, dict):
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
                ).as_dict()
            )

        traxx_cover_url = await self._cover_url_for_traxx(
            external_url=cover_url,
            local_cover=cover_path,
        )
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
        unresolved: list[dict[str, Any]] = []
        for path in files:
            local = inspect_audio_file(path)
            try:
                hint = choose_track_hint(
                    path, album_root=resolved, hints=parsed_track_hints
                )
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
                    auto_match_album=True,
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
