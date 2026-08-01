from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
from mcp_common.http import get_case_insensitive
from mcp_common.paths import resolve_contained_path
from mcp_common.rights import validate_rights

from .config import RuntimeConfig
from .metadata import AUDIO_EXTENSIONS, inspect_audio_file
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


class TraxxClient:
    def __init__(self, config: RuntimeConfig, *, downloads_dir: Path):
        self.config = config
        self.downloads_dir = downloads_dir

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

    async def import_album_folder(
        self,
        folder: str | Path,
        *,
        dry_run: bool,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
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
                "tracks": inspection,
            }
        imported: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        for path in files:
            local = inspect_audio_file(path)
            try:
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
                artist_id = self.extract_resource_id(metadata, "artist")
                album_id = self.extract_resource_id(metadata, "album")
                if not file_url or not artist_id:
                    unresolved.append(
                        {
                            "path": str(path),
                            "stage": "track-create",
                            "reason": (
                                "A playable uploaded-file URL and matched artist id "
                                "are required"
                            ),
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
                    "artists": [artist_id],
                    "src": file_url,
                    "genres": normalize_genres(
                        get_case_insensitive(metadata, "genres"),
                        fallback=local.genres,
                    ),
                }
                if album_id:
                    payload["album_id"] = album_id
                image = get_case_insensitive(metadata, "image")
                if isinstance(image, dict) and image.get("url"):
                    payload["image"] = image["url"]
                created = await self.create_track(payload)
                imported.append(
                    {
                        "path": str(path),
                        "file_entry_id": file_id,
                        "track": created,
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
