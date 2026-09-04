from __future__ import annotations

from pathlib import Path

from .client import TraxxClient, TraxxError
from .cover_network import CoverFetchError, CoverPolicyError, fetch_public_cover
from .metadata import cover_mime_type, find_local_cover


class SecureTraxxClient(TraxxClient):
    """Traxx client with a DNS-rebinding-safe external cover fetch boundary."""

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
        if not cover_url:
            return None, "image/jpeg", None

        try:
            fetched = await fetch_public_cover(
                cover_url,
                verify_tls=self.config.verify_tls,
                timeout_seconds=min(60, self.config.timeout_seconds),
            )
        except CoverPolicyError as exc:
            # Unsafe operator/upstream input must be explicit rather than
            # silently accepted as "no cover". The request is rejected before
            # any private/link-local/metadata egress occurs.
            raise TraxxError(f"Unsafe album cover URL refused: {exc}") from exc
        except CoverFetchError:
            # Preserve the existing best-effort semantics for ordinary public
            # network/HTTP failures: importing the album does not depend on a
            # remote image being available.
            return None, "image/jpeg", None

        data = fetched.data
        mime = fetched.content_type
        if not mime.startswith("image/"):
            mime = cover_mime_type(None, data)
        suffix = ".png" if mime == "image/png" else ".jpg"
        saved = album_root / f"cover{suffix}"
        if persist:
            saved.write_bytes(data)
            return data, mime, saved
        return data, mime, None


__all__ = ["SecureTraxxClient"]
