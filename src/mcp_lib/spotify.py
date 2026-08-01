from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken

from .models import SpotifyAlbumCandidate

SPOTIFY_ACCOUNTS_URL = "https://accounts.spotify.com"
SPOTIFY_API_URL = "https://api.spotify.com/v1"


class SpotifyError(RuntimeError):
    pass


class TokenCipher:
    def __init__(self, secret: str):
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, token: dict[str, Any]) -> str:
        raw = json.dumps(token, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self.fernet.encrypt(raw).decode("ascii")

    def decrypt(self, value: str) -> dict[str, Any]:
        try:
            raw = self.fernet.decrypt(value.encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            raise SpotifyError("Stored Spotify token could not be decrypted") from exc
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise SpotifyError("Stored Spotify token has an invalid format")
        return parsed


def create_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:128]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


def create_authorization_url(
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    code_challenge: str,
) -> str:
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "show_dialog": "true",
    }
    return f"{SPOTIFY_ACCOUNTS_URL}/authorize?{urlencode(params)}"


async def exchange_authorization_code(
    *,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{SPOTIFY_ACCOUNTS_URL}/api/token",
            data={
                "client_id": client_id,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code >= 400:
        raise SpotifyError(f"Spotify token exchange failed: {response.text[:1000]}")
    token = response.json()
    token["expires_at"] = int(time.time()) + int(token.get("expires_in", 3600))
    return token


async def refresh_access_token(*, client_id: str, token: dict[str, Any]) -> dict[str, Any]:
    refresh_token = token.get("refresh_token")
    if not refresh_token:
        raise SpotifyError("Spotify did not provide a refresh token; reconnect the profile")
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{SPOTIFY_ACCOUNTS_URL}/api/token",
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if response.status_code >= 400:
        raise SpotifyError(f"Spotify token refresh failed: {response.text[:1000]}")
    refreshed = response.json()
    refreshed["refresh_token"] = refreshed.get("refresh_token") or refresh_token
    refreshed["scope"] = refreshed.get("scope") or token.get("scope", "")
    refreshed["expires_at"] = int(time.time()) + int(refreshed.get("expires_in", 3600))
    return refreshed


def token_needs_refresh(token: dict[str, Any], leeway_seconds: int = 90) -> bool:
    return int(token.get("expires_at", 0) or 0) <= int(time.time()) + leeway_seconds


def _release_year(value: str) -> int | None:
    try:
        return int(value[:4])
    except (TypeError, ValueError):
        return None


def _album_from_spotify(raw: dict[str, Any], *, score: float, reasons: list[str]) -> SpotifyAlbumCandidate:
    images = raw.get("images") or []
    image_url = images[0].get("url", "") if images and isinstance(images[0], dict) else ""
    external_urls = raw.get("external_urls") or {}
    return SpotifyAlbumCandidate(
        spotify_id=str(raw.get("id") or ""),
        name=str(raw.get("name") or "Unknown Album"),
        artists=[artist for artist in raw.get("artists", []) if isinstance(artist, dict)],
        release_date=str(raw.get("release_date") or ""),
        album_type=str(raw.get("album_type") or "album"),
        total_tracks=int(raw.get("total_tracks") or 0),
        image_url=str(image_url),
        spotify_url=str(external_urls.get("spotify") or ""),
        source_reasons=list(reasons),
        score=score,
    )


def rank_album_candidates(
    candidates: list[SpotifyAlbumCandidate],
    *,
    excluded_ids: set[str] | None = None,
    excluded_keys: set[str] | None = None,
    limit: int = 5,
) -> list[SpotifyAlbumCandidate]:
    excluded_ids = excluded_ids or set()
    excluded_keys = excluded_keys or set()
    current_year = datetime.now(UTC).year
    deduplicated: dict[str, SpotifyAlbumCandidate] = {}

    for original_candidate in candidates:
        candidate = original_candidate.model_copy(deep=True)
        if not candidate.spotify_id or candidate.spotify_id in excluded_ids:
            continue
        if candidate.album_key in excluded_keys:
            continue
        if candidate.album_type not in {"album", "compilation"}:
            continue
        if candidate.total_tracks and candidate.total_tracks < 4:
            continue
        year = _release_year(candidate.release_date)
        if year:
            age = max(0, current_year - year)
            candidate.score += max(0, 12 - min(age, 12))
            if age <= 2:
                candidate.source_reasons.append("recent release")
        existing = deduplicated.get(candidate.spotify_id)
        if existing is None or candidate.score > existing.score:
            deduplicated[candidate.spotify_id] = candidate
        elif existing:
            existing.source_reasons = sorted(
                set(existing.source_reasons) | set(candidate.source_reasons)
            )

    ranked = sorted(
        deduplicated.values(),
        key=lambda item: (item.score, item.release_date, item.total_tracks),
        reverse=True,
    )
    return ranked[:limit]


class SpotifyClient:
    def __init__(self, *, client_id: str, token: dict[str, Any], timeout: float = 30):
        self.client_id = client_id
        self.token = token
        self.timeout = timeout

    async def ensure_fresh_token(self) -> tuple[dict[str, Any], bool]:
        if token_needs_refresh(self.token):
            self.token = await refresh_access_token(client_id=self.client_id, token=self.token)
            return self.token, True
        return self.token, False

    async def _get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        await self.ensure_fresh_token()
        headers = {"Authorization": f"Bearer {self.token['access_token']}"}
        async with httpx.AsyncClient(
            base_url=SPOTIFY_API_URL,
            headers=headers,
            timeout=self.timeout,
        ) as client:
            response = await client.get(path, params=params)
            if response.status_code == 429:
                retry_after = min(int(response.headers.get("Retry-After", "1")), 10)
                await asyncio.sleep(retry_after)
                response = await client.get(path, params=params)
        if response.status_code >= 400:
            raise SpotifyError(f"Spotify GET {path} failed ({response.status_code}): {response.text[:1000]}")
        result = response.json()
        if not isinstance(result, dict):
            raise SpotifyError(f"Spotify GET {path} returned an unexpected response")
        return result

    async def current_user(self) -> dict[str, Any]:
        return await self._get("/me")

    async def top_items(
        self,
        item_type: str,
        *,
        time_range: str = "medium_term",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        result = await self._get(
            f"/me/top/{item_type}",
            params={"time_range": time_range, "limit": limit},
        )
        return [item for item in result.get("items", []) if isinstance(item, dict)]

    async def saved_album_ids(self, max_items: int = 200) -> set[str]:
        offset = 0
        output: set[str] = set()
        while offset < max_items:
            result = await self._get(
                "/me/albums",
                params={"limit": min(50, max_items - offset), "offset": offset},
            )
            items = [item for item in result.get("items", []) if isinstance(item, dict)]
            for item in items:
                album = item.get("album")
                if isinstance(album, dict) and album.get("id"):
                    output.add(str(album["id"]))
            if not result.get("next") or not items:
                break
            offset += len(items)
        return output

    async def artist_albums(self, artist_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        result = await self._get(
            f"/artists/{artist_id}/albums",
            params={
                "include_groups": "album,compilation",
                "limit": min(50, limit),
            },
        )
        return [item for item in result.get("items", []) if isinstance(item, dict)]

    async def taste_profile(self) -> dict[str, Any]:
        top_artists, top_tracks = await asyncio.gather(
            self.top_items("artists", time_range="medium_term", limit=50),
            self.top_items("tracks", time_range="medium_term", limit=50),
        )
        return {
            "top_artists": top_artists,
            "top_tracks": top_tracks,
            "genres": self._genre_summary(top_artists),
        }

    @staticmethod
    def _genre_summary(artists: list[dict[str, Any]]) -> list[dict[str, Any]]:
        scores: dict[str, float] = {}
        for rank, artist in enumerate(artists):
            weight = max(1.0, 50 - rank)
            for genre in artist.get("genres", []) or []:
                scores[str(genre)] = scores.get(str(genre), 0) + weight
        return [
            {"genre": genre, "score": round(score, 2)}
            for genre, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)[:20]
        ]

    async def discover_albums(
        self,
        *,
        excluded_history_keys: set[str],
        limit: int = 5,
    ) -> tuple[dict[str, Any], list[SpotifyAlbumCandidate]]:
        taste = await self.taste_profile()
        top_artists = taste["top_artists"]
        top_tracks = taste["top_tracks"]
        listened_album_ids = {
            str(track.get("album", {}).get("id"))
            for track in top_tracks
            if isinstance(track.get("album"), dict) and track.get("album", {}).get("id")
        }
        saved_ids = await self.saved_album_ids(max_items=200)
        excluded_ids = listened_album_ids | saved_ids

        ranked_artists: list[dict[str, Any]] = []
        seen_artist_ids: set[str] = set()
        for artist in top_artists:
            artist_id = str(artist.get("id") or "")
            if artist_id and artist_id not in seen_artist_ids:
                ranked_artists.append(artist)
                seen_artist_ids.add(artist_id)
        for track in top_tracks:
            for artist in track.get("artists", []) or []:
                if not isinstance(artist, dict):
                    continue
                artist_id = str(artist.get("id") or "")
                if artist_id and artist_id not in seen_artist_ids:
                    ranked_artists.append(artist)
                    seen_artist_ids.add(artist_id)
        ranked_artists = ranked_artists[:18]

        semaphore = asyncio.Semaphore(4)

        async def load(rank: int, artist: dict[str, Any]) -> list[SpotifyAlbumCandidate]:
            artist_id = str(artist.get("id") or "")
            artist_name = str(artist.get("name") or "Unknown Artist")
            async with semaphore:
                albums = await self.artist_albums(artist_id, limit=30)
            output: list[SpotifyAlbumCandidate] = []
            base_score = max(20.0, 130.0 - (rank * 4.0))
            for raw_album in albums:
                candidate = _album_from_spotify(
                    raw_album,
                    score=base_score,
                    reasons=[f"matches top artist #{rank + 1}: {artist_name}"],
                )
                output.append(candidate)
            return output

        loaded = await asyncio.gather(
            *(load(rank, artist) for rank, artist in enumerate(ranked_artists)),
            return_exceptions=True,
        )
        candidates: list[SpotifyAlbumCandidate] = []
        errors: list[str] = []
        for result in loaded:
            if isinstance(result, Exception):
                errors.append(str(result))
            else:
                candidates.extend(result)

        ranked = rank_album_candidates(
            candidates,
            excluded_ids=excluded_ids,
            excluded_keys=excluded_history_keys,
            limit=limit,
        )
        analysis = {
            "top_artists": [
                {"id": artist.get("id"), "name": artist.get("name")}
                for artist in top_artists[:20]
            ],
            "top_tracks": [
                {
                    "id": track.get("id"),
                    "name": track.get("name"),
                    "artist": (track.get("artists") or [{}])[0].get("name"),
                }
                for track in top_tracks[:20]
            ],
            "genres": taste["genres"],
            "excluded_known_albums": len(excluded_ids),
            "candidate_pool": len(candidates),
            "partial_errors": errors,
        }
        return analysis, ranked
