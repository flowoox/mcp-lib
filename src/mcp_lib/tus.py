from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx


class TusError(RuntimeError):
    pass


@dataclass(slots=True)
class TusUploadResult:
    upload_url: str
    bytes_uploaded: int
    file_entry_id: str | None = None
    file_url: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_json: dict[str, Any] | None = None


class TusUploader:
    def __init__(
        self,
        *,
        endpoint: str,
        headers: dict[str, str] | None = None,
        verify_tls: bool = True,
        chunk_size: int = 8 * 1024 * 1024,
        timeout: float = 120,
    ):
        self.endpoint = endpoint
        self.headers = headers or {}
        self.verify_tls = verify_tls
        self.chunk_size = chunk_size
        self.timeout = timeout

    @staticmethod
    def _encode_metadata(metadata: dict[str, str]) -> str:
        encoded: list[str] = []
        for key, value in metadata.items():
            key = key.strip()
            if not key:
                continue
            base64_value = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
            encoded.append(f"{key} {base64_value}")
        return ",".join(encoded)

    @staticmethod
    def _extract_file_entry_id(headers: dict[str, str], upload_url: str) -> str | None:
        lowered = {key.casefold(): value for key, value in headers.items()}
        for key in (
            "x-file-entry-id",
            "file-entry-id",
            "x-resource-id",
            "resource-id",
            "upload-id",
        ):
            value = lowered.get(key)
            if value:
                return value.strip()
        segment = urlparse(upload_url).path.rstrip("/").rsplit("/", 1)[-1]
        return segment if segment.isdigit() else None

    async def _head_offset(self, client: httpx.AsyncClient, upload_url: str) -> int:
        response = await client.head(
            upload_url,
            headers={**self.headers, "Tus-Resumable": "1.0.0"},
        )
        if response.status_code >= 400:
            raise TusError(f"TUS HEAD failed ({response.status_code}): {response.text[:500]}")
        try:
            return int(response.headers.get("Upload-Offset", "0"))
        except ValueError as exc:
            raise TusError("TUS server returned an invalid Upload-Offset") from exc

    async def upload(
        self,
        path: Path,
        *,
        upload_type: str = "track",
        extra_metadata: dict[str, str] | None = None,
    ) -> TusUploadResult:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        metadata = {
            "filename": path.name,
            "filetype": mime,
            "uploadType": upload_type,
            "clientName": path.name,
            "clientMime": mime,
            "clientSize": str(size),
        }
        metadata.update(extra_metadata or {})

        create_headers = {
            **self.headers,
            "Tus-Resumable": "1.0.0",
            "Upload-Length": str(size),
            "Upload-Metadata": self._encode_metadata(metadata),
        }

        async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout) as client:
            create_response = await client.post(self.endpoint, headers=create_headers)
            if create_response.status_code not in {201, 204}:
                raise TusError(
                    f"TUS create failed ({create_response.status_code}): "
                    f"{create_response.text[:1000]}"
                )
            location = create_response.headers.get("Location")
            if not location:
                raise TusError("TUS create response did not include a Location header")
            upload_url = urljoin(str(create_response.url), location)
            offset = 0
            response_headers = dict(create_response.headers)
            response_json: dict[str, Any] | None = None
            if create_response.content:
                try:
                    parsed = create_response.json()
                    if isinstance(parsed, dict):
                        response_json = parsed
                except ValueError:
                    pass

            with path.open("rb") as stream:
                while offset < size:
                    stream.seek(offset)
                    chunk = stream.read(min(self.chunk_size, size - offset))
                    patch_headers = {
                        **self.headers,
                        "Tus-Resumable": "1.0.0",
                        "Upload-Offset": str(offset),
                        "Content-Type": "application/offset+octet-stream",
                    }
                    response = await client.patch(upload_url, headers=patch_headers, content=chunk)
                    if response.status_code in {409, 412}:
                        offset = await self._head_offset(client, upload_url)
                        continue
                    if response.status_code not in {204, 200}:
                        raise TusError(
                            f"TUS PATCH failed ({response.status_code}) at offset {offset}: "
                            f"{response.text[:1000]}"
                        )
                    try:
                        new_offset = int(response.headers.get("Upload-Offset", offset + len(chunk)))
                    except ValueError as exc:
                        raise TusError("TUS server returned an invalid Upload-Offset") from exc
                    if new_offset <= offset:
                        raise TusError("TUS upload did not advance")
                    offset = new_offset
                    response_headers.update(dict(response.headers))
                    if response.content:
                        try:
                            parsed = response.json()
                            if isinstance(parsed, dict):
                                response_json = parsed
                        except ValueError:
                            pass

        file_entry_id = self._extract_file_entry_id(response_headers, upload_url)
        file_url = None
        lowered = {key.casefold(): value for key, value in response_headers.items()}
        for key in ("x-file-url", "file-url", "resource-url"):
            if lowered.get(key):
                file_url = lowered[key]
                break
        if response_json:
            file_entry_id = str(
                response_json.get("fileEntryId")
                or response_json.get("file_entry_id")
                or response_json.get("id")
                or file_entry_id
                or ""
            ) or None
            file_url = (
                response_json.get("fileUrl")
                or response_json.get("file_url")
                or response_json.get("url")
                or file_url
            )

        return TusUploadResult(
            upload_url=upload_url,
            bytes_uploaded=offset,
            file_entry_id=file_entry_id,
            file_url=str(file_url) if file_url else None,
            response_headers=response_headers,
            response_json=response_json,
        )
