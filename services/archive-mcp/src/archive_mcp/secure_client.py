from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from urllib.parse import quote, urljoin

import httpx

from .client import ArchiveClient, ArchiveError
from .models import ArchiveFile, DownloadBatch
from .network import (
    MAX_REDIRECTS,
    REDIRECT_STATUS_CODES,
    ArchiveOutboundError,
    validate_archive_outbound_url,
)

UrlValidator = Callable[[str], Awaitable[None]]


class SecureArchiveClient(ArchiveClient):
    """Archive client with an explicit fail-closed outbound trust boundary.

    The base configuration is locked to ``https://archive.org``. Every actual
    request target, including every redirect hop, is validated again before it
    is sent. HTTPX automatic redirects stay disabled at the individual send so
    a 30x cannot jump the policy check.
    """

    def __init__(
        self,
        *args: object,
        url_validator: UrlValidator = validate_archive_outbound_url,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.url_validator = url_validator

    async def _send_with_validated_redirects(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        params: dict[str, object] | list[tuple[str, object]] | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        current_url = url
        current_params = params
        for redirect_count in range(MAX_REDIRECTS + 1):
            try:
                await self.url_validator(current_url)
            except ArchiveOutboundError as exc:
                raise ArchiveError(f"Archive outbound request blocked: {exc}") from exc

            request = client.build_request(
                "GET",
                current_url,
                params=current_params,
            )
            response = await client.send(
                request,
                stream=stream,
                follow_redirects=False,
            )
            current_params = None
            if response.status_code not in REDIRECT_STATUS_CODES:
                return response

            location = response.headers.get("location")
            await response.aclose()
            if not location:
                raise ArchiveError("Archive redirect did not contain a Location header")
            if redirect_count >= MAX_REDIRECTS:
                raise ArchiveError("Archive request exceeded the redirect limit")
            current_url = urljoin(str(response.url), location)

        raise ArchiveError("Archive request exceeded the redirect limit")

    async def request_json(
        self,
        path: str,
        *,
        params: dict[str, object] | list[tuple[str, object]] | None = None,
    ) -> object:
        if not path.startswith("/"):
            raise ArchiveError("Archive API path must be absolute")
        url = f"{self.config.base_url}{path}"
        async with httpx.AsyncClient(
            headers=self.headers,
            timeout=self.config.search_timeout + 15,
            follow_redirects=False,
        ) as client:
            response = await self._send_with_validated_redirects(
                client,
                url,
                params=params,
            )
        if response.status_code >= 400:
            # Do not relay an upstream body into MCP error output. A storage
            # node may include internal/provider diagnostics not meant for a
            # caller.
            raise ArchiveError(f"archive.org GET {path} failed ({response.status_code})")
        try:
            return response.json()
        except ValueError as exc:
            raise ArchiveError(f"archive.org GET {path} returned invalid JSON") from exc

    async def fetch_cover(
        self,
        record: DownloadBatch,
        client: httpx.AsyncClient,
        target: Path,
    ) -> None:
        if not record.cover_name:
            return
        suffix = Path(record.cover_name).suffix.casefold() or ".jpg"
        destination = target / f"cover{suffix}"
        if destination.exists():
            return
        url = (
            f"{self.config.base_url}/download/{quote(record.identifier, safe='')}/"
            f"{quote(record.cover_name, safe='/')}"
        )
        response: httpx.Response | None = None
        try:
            response = await self._send_with_validated_redirects(client, url)
            response.raise_for_status()
            destination.write_bytes(response.content)
        except Exception:  # noqa: BLE001 - artwork is optional
            return
        finally:
            if response is not None:
                await response.aclose()

    async def fetch_file(
        self,
        client: httpx.AsyncClient,
        identifier: str,
        file: ArchiveFile,
        local: Path,
    ) -> int:
        url = (
            f"{self.config.base_url}/download/{quote(identifier, safe='')}/"
            f"{quote(file.name, safe='/')}"
        )
        temporary = local.with_name(local.name + ".part")
        digest = hashlib.md5()  # noqa: S324 - Archive metadata integrity check only
        written = 0
        response = await self._send_with_validated_redirects(client, url, stream=True)
        try:
            if response.status_code >= 400:
                raise ArchiveError(
                    f"archive.org download {file.name} failed ({response.status_code})"
                )
            with temporary.open("wb") as handle:
                async for chunk in response.aiter_bytes(262_144):
                    handle.write(chunk)
                    digest.update(chunk)
                    written += len(chunk)
        finally:
            await response.aclose()

        if file.size and written != file.size:
            with suppress(OSError):
                temporary.unlink()
            raise ArchiveError(f"{file.name}: {written} statt {file.size} Bytes empfangen")
        if file.md5 and digest.hexdigest() != file.md5:
            with suppress(OSError):
                temporary.unlink()
            raise ArchiveError(f"{file.name}: md5 stimmt nicht mit den Metadaten überein")
        temporary.replace(local)
        return written


__all__ = ["SecureArchiveClient"]
