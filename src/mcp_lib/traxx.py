from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
from mutagen import File as MutagenFile

from .rights import validate_rights
from .tus import TusUploader, TusUploadResult
from .utils import get_case_insensitive, resolve_contained_path

AUDIO_EXTENSIONS = {".flac", ".wav", ".aiff", ".aif", ".ape", ".wv", ".mp3", ".m4a", ".ogg", ".opus"}


class TraxxError(RuntimeError):
    pass


@dataclass(slots=True)
class LocalAudioMetadata:
    title: str
    artist: str
    album: str
    duration_ms: int
    track_number: int
    genres: list[str]


def _first_tag(tags: Any, *keys: str) -> str:
    if not tags:
        return ""
    for key in keys:
        value = tags.get(key)
        if value:
            if isinstance(value, list):
                return str(value[0])
            return str(value)
    return ""


def normalize_genres(value: Any, fallback: list[str] | None = None) -> list[str]:
    """Normalize BeMusic/getID3 genre payloads into the string list expected by Traxx."""
    if value is None:
        return list(fallback or [])
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if not isinstance(value, list):
        return list(fallback or [])

    normalized: list[str] = []
    for item in value:
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, dict):
            name = str(
                get_case_insensitive(item, "name", "display_name", "displayName", default="")
                or ""
            ).strip()
        else:
            name = str(item).strip()
        if name and name not in normalized:
            normalized.append(name)
    return normalized or list(fallback or [])


def inspect_audio_file(path: Path) -> LocalAudioMetadata:
    audio = MutagenFile(path, easy=True)
    tags = getattr(audio, "tags", {}) or {}
    info = getattr(audio, "info", None)
    duration_ms = int(max(1, float(getattr(info, "length", 0) or 0) * 1000))
    track_raw = _first_tag(tags, "tracknumber", "track")
    match = re.search(r"\d+", track_raw)
    track_number = int(match.group(0)) if match else 1
    genres_raw = tags.get("genre", []) if tags else []
    if isinstance(genres_raw, str):
        genres = [part.strip() for part in genres_raw.split(",") if part.strip()]
    else:
        genres = [str(item).strip() for item in genres_raw if str(item).strip()]
    return LocalAudioMetadata(
        title=_first_tag(tags, "title") or path.stem,
        artist=_first_tag(tags, "artist", "albumartist") or "Unknown Artist",
        album=_first_tag(tags, "album") or path.parent.name,
        duration_ms=duration_ms,
        track_number=track_number,
        genres=genres,
    )


class TraxxClient:
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        tus_endpoint: str = "/api/v1/tus/",
        verify_tls: bool = True,
        upload_chunk_size: int = 8 * 1024 * 1024,
        file_url_template: str = "",
        downloads_dir: Path = Path("/downloads"),
        timeout: float = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.tus_endpoint = tus_endpoint
        self.verify_tls = verify_tls
        self.upload_chunk_size = upload_chunk_size
        self.file_url_template = file_url_template
        self.downloads_dir = downloads_dir
        self.timeout = timeout

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        if not self.base_url:
            raise TraxxError("TRAXX_URL is not configured")
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            verify=self.verify_tls,
            timeout=self.timeout,
        ) as client:
            response = await client.request(method, path, json=json, params=params)
        if response.status_code >= 400:
            raise TraxxError(
                f"Traxx {method} {path} failed ({response.status_code}): {response.text[:1000]}"
            )
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return {"text": response.text}

    async def health(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/v1/tracks", params={"perPage": 1})
        return {"ok": True, "api": "/api/v1/tracks", "response_type": type(data).__name__}

    async def list_tracks(self, *, page: int = 1, per_page: int = 20, query: str = "") -> Any:
        params: dict[str, Any] = {"page": page, "perPage": per_page}
        if query:
            params["query"] = query
        return await self._request("GET", "/api/v1/tracks", params=params)

    async def list_albums(self, *, page: int = 1, per_page: int = 20, query: str = "") -> Any:
        params: dict[str, Any] = {"page": page, "perPage": per_page}
        if query:
            params["query"] = query
        return await self._request("GET", "/api/v1/albums", params=params)

    async def import_spotify_metadata(self, *, model_type: str, spotify_id: str) -> Any:
        payload = {
            "modelType": model_type,
            "metadataProvider": "spotify",
            "spotifyId": spotify_id,
        }
        return await self._request("POST", "/api/v1/import-media/single-item", json=payload)

    def _resolve_file_url(self, result: TusUploadResult) -> str | None:
        if result.file_url:
            return str(result.file_url)
        if not self.file_url_template:
            return None
        return self.file_url_template.format(
            file_entry_id=result.file_entry_id or "",
            upload_url=result.upload_url,
            base_url=self.base_url,
        )

    async def upload_file(self, path: Path, *, upload_type: str = "track") -> dict[str, Any]:
        endpoint = urljoin(f"{self.base_url}/", self.tus_endpoint.lstrip("/"))
        uploader = TusUploader(
            endpoint=endpoint,
            headers=self.headers,
            verify_tls=self.verify_tls,
            chunk_size=self.upload_chunk_size,
            timeout=max(self.timeout, 300),
        )
        result = await uploader.upload(path, upload_type=upload_type)
        return {
            "upload_url": result.upload_url,
            "bytes_uploaded": result.bytes_uploaded,
            "file_entry_id": result.file_entry_id,
            "file_url": self._resolve_file_url(result),
            "response_json": result.response_json,
        }

    async def extract_file_metadata(self, file_entry_id: str, *, auto_match_album: bool = True) -> Any:
        return await self._request(
            "POST",
            f"/api/v1/tracks/{file_entry_id}/extract-metadata",
            json={"autoMatchAlbum": auto_match_album},
        )

    @staticmethod
    def _extract_resource_id(value: Any, resource: str) -> int | None:
        if not isinstance(value, dict):
            return None
        direct = get_case_insensitive(value, resource)
        if isinstance(direct, dict):
            candidate = get_case_insensitive(direct, "id")
            try:
                return int(candidate)
            except (TypeError, ValueError):
                return None
        return None

    async def create_track(self, payload: dict[str, Any]) -> Any:
        return await self._request("POST", "/api/v1/tracks", json=payload)

    async def import_album_folder(
        self,
        folder: str | Path,
        *,
        dry_run: bool = True,
        rights_confirmed: bool,
        rights_basis: str,
        rights_reference: str = "",
    ) -> dict[str, Any]:
        rights = validate_rights(
            confirmed=rights_confirmed,
            basis=rights_basis,
            reference=rights_reference,
        )
        resolved_folder = resolve_contained_path(self.downloads_dir, folder)
        if not resolved_folder.is_dir():
            raise FileNotFoundError(resolved_folder)
        files = sorted(
            path
            for path in resolved_folder.rglob("*")
            if path.is_file() and path.suffix.casefold() in AUDIO_EXTENSIONS
        )
        if not files:
            raise TraxxError(f"No supported audio files found in {resolved_folder}")

        inspected = [
            {
                "path": str(path),
                "metadata": asdict(inspect_audio_file(path)),
            }
            for path in files
        ]
        if dry_run:
            return {
                "dry_run": True,
                "folder": str(resolved_folder),
                "track_count": len(files),
                "rights": {"basis": rights.basis, "reference": rights.reference},
                "tracks": inspected,
            }

        imported: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        for path in files:
            local = inspect_audio_file(path)
            upload = await self.upload_file(path, upload_type="track")
            file_entry_id = upload.get("file_entry_id")
            file_url = upload.get("file_url")
            if not file_entry_id:
                unresolved.append(
                    {
                        "path": str(path),
                        "stage": "upload",
                        "reason": "Traxx TUS response did not expose a file-entry id.",
                        "upload": upload,
                    }
                )
                continue

            extracted = await self.extract_file_metadata(str(file_entry_id), auto_match_album=True)
            metadata = extracted.get("metadata", extracted) if isinstance(extracted, dict) else {}
            artist_id = self._extract_resource_id(metadata, "artist")
            album_id = self._extract_resource_id(metadata, "album")
            if not file_url or not artist_id:
                unresolved.append(
                    {
                        "path": str(path),
                        "stage": "track-create",
                        "reason": (
                            "A playable file URL and matched artist id are required. "
                            "Set TRAXX_FILE_URL_TEMPLATE after the first live TUS probe if needed."
                        ),
                        "upload": upload,
                        "metadata": metadata,
                    }
                )
                continue

            duration = int(get_case_insensitive(metadata, "duration", default=local.duration_ms) or local.duration_ms)
            title = str(get_case_insensitive(metadata, "title", "name", default=local.title) or local.title)
            number = get_case_insensitive(metadata, "track_number", "tracknumber", "number", default=local.track_number)
            try:
                number = int(str(number).split("/", 1)[0])
            except (TypeError, ValueError):
                number = local.track_number
            track_payload: dict[str, Any] = {
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
                track_payload["album_id"] = album_id
            image = get_case_insensitive(metadata, "image")
            if isinstance(image, dict) and image.get("url"):
                track_payload["image"] = image["url"]
            created = await self.create_track(track_payload)
            imported.append(
                {
                    "path": str(path),
                    "file_entry_id": file_entry_id,
                    "track": created,
                }
            )

        return {
            "dry_run": False,
            "folder": str(resolved_folder),
            "track_count": len(files),
            "imported_count": len(imported),
            "unresolved_count": len(unresolved),
            "rights": {"basis": rights.basis, "reference": rights.reference},
            "imported": imported,
            "unresolved": unresolved,
        }
