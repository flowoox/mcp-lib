from __future__ import annotations

import base64
import mimetypes
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx


class TusUnsupported(RuntimeError):
    """The endpoint answered, but not as a TUS server.

    Separated from a genuine upload failure because the two need opposite
    responses: a failure should be reported, while an instance that simply
    has no TUS route should be uploaded to the ordinary way.
    """

    def __init__(self, message: str, *, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class TusError(RuntimeError):
    pass


@dataclass(slots=True)
class TusUploadResult:
    upload_url: str
    bytes_uploaded: int
    file_entry_id: str | None = None
    file_url: str | None = None
    create_status: int = 0
    final_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_json: dict[str, Any] | None = None
    head_headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def recursive_find(value: Any, names: set[str]) -> Any:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in names and child not in (None, ""):
                return child
        for child in value.values():
            found = recursive_find(child, names)
            if found not in (None, ""):
                return found
    elif isinstance(value, list):
        for child in value:
            found = recursive_find(child, names)
            if found not in (None, ""):
                return found
    return None


class TusUploader:
    def __init__(
        self,
        *,
        endpoint: str,
        headers: dict[str, str],
        verify_tls: bool,
        chunk_size: int,
        timeout: float,
    ):
        self.endpoint = endpoint
        self.headers = headers
        self.verify_tls = verify_tls
        self.chunk_size = chunk_size
        self.timeout = timeout

    @staticmethod
    def encode_metadata(metadata: dict[str, str]) -> str:
        return ",".join(
            f"{key.strip()} {base64.b64encode(str(value).encode()).decode('ascii')}"
            for key, value in metadata.items()
            if key.strip()
        )

    @staticmethod
    def resolve_upload_url(
        endpoint: str,
        created_url: str,
        location: str,
        headers: dict[str, str],
    ) -> str:
        """Keep a public TUS Location on the reachable internal origin.

        BeMusic uses the forwarded Host header when it creates an absolute
        Location. Internal clients still need to PATCH the same service via
        its Docker address; routing the public URL back through the edge can
        fail on hosts without NAT hairpinning. Only the explicitly forwarded
        host is rewritten, so genuine external upload targets remain intact.
        """
        resolved = urljoin(created_url, location)
        endpoint_url = urlparse(endpoint)
        location_url = urlparse(resolved)
        forwarded_host = next(
            (
                value
                for key, value in headers.items()
                if key.casefold() == "host"
            ),
            "",
        )
        forwarded_hostname = urlparse(f"//{forwarded_host}").hostname
        if (
            endpoint_url.scheme
            and endpoint_url.netloc
            and forwarded_hostname
            and location_url.hostname
            and location_url.hostname.casefold() == forwarded_hostname.casefold()
            and location_url.hostname.casefold()
            != (endpoint_url.hostname or "").casefold()
        ):
            return location_url._replace(
                scheme=endpoint_url.scheme,
                netloc=endpoint_url.netloc,
            ).geturl()
        return resolved

    @staticmethod
    def extract_identity(
        headers: dict[str, str],
        upload_url: str,
        payload: dict[str, Any] | None,
    ) -> tuple[str | None, str | None]:
        lowered = {key.casefold(): value for key, value in headers.items()}
        file_id = next(
            (
                lowered[key]
                for key in (
                    "x-file-entry-id",
                    "file-entry-id",
                    "x-resource-id",
                    "resource-id",
                )
                if lowered.get(key)
            ),
            None,
        )
        file_url = next(
            (
                lowered[key]
                for key in ("x-file-url", "file-url", "resource-url")
                if lowered.get(key)
            ),
            None,
        )
        if payload:
            file_id = (
                recursive_find(
                    payload,
                    {
                        "fileentryid",
                        "file_entry_id",
                        "fileentry_id",
                        "resourceid",
                        "id",
                    },
                )
                or file_id
            )
            file_url = (
                recursive_find(
                    payload,
                    {
                        "fileurl",
                        "file_url",
                        "downloadurl",
                        "download_url",
                        "url",
                    },
                )
                or file_url
            )
        segment = urlparse(upload_url).path.rstrip("/").rsplit("/", 1)[-1]
        if not file_id and segment.isdigit():
            file_id = segment
        return (
            str(file_id) if file_id else None,
            str(file_url) if file_url else None,
        )

    async def upload(
        self,
        path: Path,
        *,
        upload_type: str = "media",
        extra_metadata: dict[str, str] | None = None,
    ) -> TusUploadResult:
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        metadata = {
            # No "filename" on purpose. The server takes that conventional TUS
            # key as the literal storage path, so a second album with a track
            # called "01 Intro.flac" collided with the first and the upload
            # failed. Left out, the server assigns a uuid of its own and the
            # readable title still comes from clientName.
            "uploadType": upload_type,
            "clientName": path.name,
            # clientExtension, clientMime and clientSize are not decoration:
            # measured against the live server, leaving any one of them out
            # makes the create step answer 500 before a byte is sent.
            "clientExtension": path.suffix.lstrip(".").casefold(),
            "clientMime": mime,
            "clientSize": str(size),
        }
        metadata.update(extra_metadata or {})
        create_headers = {
            **self.headers,
            "Tus-Resumable": "1.0.0",
            "Upload-Length": str(size),
            "Upload-Metadata": self.encode_metadata(metadata),
        }
        response_headers: dict[str, str] = {}
        response_json: dict[str, Any] | None = None
        final_status = 0
        head_headers: dict[str, str] = {}
        async with httpx.AsyncClient(
            verify=self.verify_tls,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            created = await client.post(self.endpoint, headers=create_headers)
            # 404/405 mean the route is not a TUS server at all — BeMusic
            # without the TUS add-on answers its SPA catch-all here. That is a
            # different situation from an upload that was attempted and
            # refused, and the caller can still use the ordinary route.
            if created.status_code in {404, 405}:
                raise TusUnsupported(
                    f"No TUS server at {self.endpoint} ({created.status_code})",
                    status_code=created.status_code,
                )
            if created.status_code not in {201, 204}:
                raise TusError(
                    f"TUS create failed ({created.status_code}): {created.text[:1400]}"
                )
            location = created.headers.get("Location")
            if not location:
                raise TusError("TUS create response did not include a Location header")
            upload_url = self.resolve_upload_url(
                self.endpoint,
                str(created.url),
                location,
                self.headers,
            )
            response_headers.update(dict(created.headers))
            if created.content:
                try:
                    parsed = created.json()
                    response_json = parsed if isinstance(parsed, dict) else None
                except ValueError:
                    pass
            offset = 0
            with path.open("rb") as stream:
                while offset < size:
                    stream.seek(offset)
                    chunk = stream.read(min(self.chunk_size, size - offset))
                    patch = await client.patch(
                        upload_url,
                        headers={
                            **self.headers,
                            "Tus-Resumable": "1.0.0",
                            "Upload-Offset": str(offset),
                            "Content-Type": "application/offset+octet-stream",
                        },
                        content=chunk,
                    )
                    final_status = patch.status_code
                    if patch.status_code in {409, 412}:
                        head = await client.head(
                            upload_url,
                            headers={**self.headers, "Tus-Resumable": "1.0.0"},
                        )
                        if head.status_code >= 400:
                            raise TusError(
                                f"TUS HEAD failed ({head.status_code}): {head.text[:800]}"
                            )
                        offset = int(head.headers.get("Upload-Offset", "0"))
                        continue
                    if patch.status_code not in {200, 204}:
                        raise TusError(
                            f"TUS PATCH failed ({patch.status_code}) at {offset}: "
                            f"{patch.text[:1400]}"
                        )
                    new_offset = int(
                        patch.headers.get("Upload-Offset", offset + len(chunk))
                    )
                    if new_offset <= offset:
                        raise TusError("TUS upload did not advance")
                    offset = new_offset
                    response_headers.update(dict(patch.headers))
                    if patch.content:
                        try:
                            parsed = patch.json()
                            if isinstance(parsed, dict):
                                response_json = parsed
                        except ValueError:
                            pass
            head = await client.head(
                upload_url,
                headers={**self.headers, "Tus-Resumable": "1.0.0"},
            )
            if head.status_code < 400:
                head_headers = dict(head.headers)
                response_headers.update(head_headers)
        file_id, file_url = self.extract_identity(
            response_headers,
            upload_url,
            response_json,
        )
        return TusUploadResult(
            upload_url=upload_url,
            bytes_uploaded=offset,
            file_entry_id=file_id,
            file_url=file_url,
            create_status=created.status_code,
            final_status=final_status,
            response_headers=response_headers,
            response_json=response_json,
            head_headers=head_headers,
        )
