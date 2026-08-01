from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .models import AlbumCandidate, Recommendation
from .utils import iso_now, parse_json, stable_id


class StateStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS album_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                );

                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    verifier TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY,
                    spotify_user_id TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    email TEXT,
                    encrypted_token TEXT NOT NULL,
                    selected INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS recommendations (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    spotify_album_id TEXT NOT NULL,
                    artist TEXT NOT NULL,
                    album TEXT NOT NULL,
                    release_date TEXT,
                    image_url TEXT,
                    spotify_url TEXT,
                    score REAL NOT NULL DEFAULT 0,
                    source_reasons_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'recommended',
                    candidate_id TEXT,
                    slskd_batch_id TEXT,
                    local_path TEXT,
                    rights_basis TEXT,
                    rights_reference TEXT,
                    traxx_result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(profile_id, spotify_album_id),
                    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS album_history (
                    profile_id TEXT NOT NULL,
                    album_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    PRIMARY KEY(profile_id, album_key)
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_recommendations_status
                    ON recommendations(status, updated_at);
                CREATE INDEX IF NOT EXISTS idx_recommendations_profile
                    ON recommendations(profile_id, created_at DESC);
                """
            )

    # Album candidates -------------------------------------------------
    def save_candidate(self, candidate: AlbumCandidate) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO album_candidates(candidate_id, payload_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(candidate_id) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (candidate.candidate_id, candidate.model_dump_json(), iso_now()),
            )

    def get_candidate(self, candidate_id: str) -> AlbumCandidate | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM album_candidates WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
        return AlbumCandidate.model_validate_json(row["payload_json"]) if row else None

    # OAuth -------------------------------------------------------------
    def save_oauth_state(self, state: str, verifier: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO oauth_states(state, verifier, created_at) VALUES (?, ?, ?)",
                (state, verifier, iso_now()),
            )

    def pop_oauth_state(self, state: str) -> str | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT verifier FROM oauth_states WHERE state = ?",
                (state,),
            ).fetchone()
            connection.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        return str(row["verifier"]) if row else None

    # Profiles ----------------------------------------------------------
    def upsert_profile(
        self,
        *,
        spotify_user_id: str,
        display_name: str,
        email: str,
        encrypted_token: str,
    ) -> str:
        profile_id = stable_id("spotify-profile", spotify_user_id)
        now = iso_now()
        with self.connect() as connection:
            existing_count = connection.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
            connection.execute(
                """
                INSERT INTO profiles(
                    id, spotify_user_id, display_name, email, encrypted_token,
                    selected, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(spotify_user_id) DO UPDATE SET
                    display_name=excluded.display_name,
                    email=excluded.email,
                    encrypted_token=excluded.encrypted_token,
                    updated_at=excluded.updated_at
                """,
                (
                    profile_id,
                    spotify_user_id,
                    display_name,
                    email,
                    encrypted_token,
                    1 if existing_count == 0 else 0,
                    now,
                    now,
                ),
            )
        return profile_id

    def list_profiles(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, spotify_user_id, display_name, email, selected, created_at, updated_at
                FROM profiles ORDER BY selected DESC, display_name COLLATE NOCASE
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
        return dict(row) if row else None

    def get_selected_profile(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM profiles WHERE selected = 1 ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def set_selected_profile(self, profile_id: str) -> None:
        with self.connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM profiles WHERE id = ?",
                (profile_id,),
            ).fetchone()
            if not exists:
                raise KeyError(f"Unknown profile: {profile_id}")
            connection.execute("UPDATE profiles SET selected = 0")
            connection.execute(
                "UPDATE profiles SET selected = 1, updated_at = ? WHERE id = ?",
                (iso_now(), profile_id),
            )

    def update_profile_token(self, profile_id: str, encrypted_token: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE profiles SET encrypted_token = ?, updated_at = ? WHERE id = ?",
                (encrypted_token, iso_now(), profile_id),
            )

    # Recommendations --------------------------------------------------
    def upsert_recommendation(self, recommendation: Recommendation) -> str:
        now = iso_now()
        created_at = recommendation.created_at.isoformat() if recommendation.created_at else now
        updated_at = recommendation.updated_at.isoformat() if recommendation.updated_at else now
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO recommendations(
                    id, profile_id, spotify_album_id, artist, album, release_date,
                    image_url, spotify_url, score, source_reasons_json, status,
                    candidate_id, slskd_batch_id, local_path, rights_basis,
                    rights_reference, traxx_result_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile_id, spotify_album_id) DO UPDATE SET
                    artist=excluded.artist,
                    album=excluded.album,
                    release_date=excluded.release_date,
                    image_url=excluded.image_url,
                    spotify_url=excluded.spotify_url,
                    score=excluded.score,
                    source_reasons_json=excluded.source_reasons_json,
                    updated_at=excluded.updated_at
                """,
                (
                    recommendation.id,
                    recommendation.profile_id,
                    recommendation.spotify_album_id,
                    recommendation.artist,
                    recommendation.album,
                    recommendation.release_date,
                    recommendation.image_url,
                    recommendation.spotify_url,
                    recommendation.score,
                    json.dumps(recommendation.source_reasons, ensure_ascii=False),
                    recommendation.status,
                    recommendation.candidate_id,
                    recommendation.slskd_batch_id,
                    recommendation.local_path,
                    recommendation.rights_basis,
                    recommendation.rights_reference,
                    json.dumps(recommendation.traxx_result, ensure_ascii=False)
                    if recommendation.traxx_result is not None
                    else None,
                    created_at,
                    updated_at,
                ),
            )
        return recommendation.id

    def get_recommendation(self, recommendation_id: str) -> Recommendation | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM recommendations WHERE id = ?",
                (recommendation_id,),
            ).fetchone()
        return self._recommendation_from_row(row) if row else None

    def list_recommendations(
        self,
        *,
        profile_id: str | None = None,
        statuses: list[str] | None = None,
        limit: int = 100,
    ) -> list[Recommendation]:
        clauses: list[str] = []
        params: list[Any] = []
        if profile_id:
            clauses.append("profile_id = ?")
            params.append(profile_id)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(statuses)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM recommendations {where} ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._recommendation_from_row(row) for row in rows]

    def update_recommendation(self, recommendation_id: str, **fields: Any) -> None:
        allowed = {
            "status",
            "candidate_id",
            "slskd_batch_id",
            "local_path",
            "rights_basis",
            "rights_reference",
            "traxx_result_json",
        }
        updates: list[str] = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"Unsupported recommendation field: {key}")
            if key == "traxx_result_json" and not isinstance(value, str):
                value = json.dumps(value, ensure_ascii=False)
            updates.append(f"{key} = ?")
            params.append(value)
        if not updates:
            return
        updates.append("updated_at = ?")
        params.append(iso_now())
        params.append(recommendation_id)
        with self.connect() as connection:
            connection.execute(
                f"UPDATE recommendations SET {', '.join(updates)} WHERE id = ?",
                params,
            )

    @staticmethod
    def _recommendation_from_row(row: sqlite3.Row) -> Recommendation:
        return Recommendation(
            id=row["id"],
            profile_id=row["profile_id"],
            spotify_album_id=row["spotify_album_id"],
            artist=row["artist"],
            album=row["album"],
            release_date=row["release_date"] or "",
            image_url=row["image_url"] or "",
            spotify_url=row["spotify_url"] or "",
            score=float(row["score"] or 0),
            source_reasons=parse_json(row["source_reasons_json"], []),
            status=row["status"],
            candidate_id=row["candidate_id"],
            slskd_batch_id=row["slskd_batch_id"],
            local_path=row["local_path"],
            rights_basis=row["rights_basis"] or "",
            rights_reference=row["rights_reference"] or "",
            traxx_result=parse_json(row["traxx_result_json"], None),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # History and jobs -------------------------------------------------
    def history_keys(self, profile_id: str) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT album_key FROM album_history WHERE profile_id = ?",
                (profile_id,),
            ).fetchall()
        return {str(row["album_key"]) for row in rows}

    def add_history(self, profile_id: str, album_key: str, status: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO album_history(profile_id, album_key, status, added_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(profile_id, album_key) DO UPDATE SET
                    status=excluded.status,
                    added_at=excluded.added_at
                """,
                (profile_id, album_key, status, iso_now()),
            )

    def start_job(self, kind: str, details: dict[str, Any] | None = None) -> str:
        job_id = stable_id(kind, iso_now())
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO jobs(id, kind, status, details_json, started_at) VALUES (?, ?, ?, ?, ?)",
                (job_id, kind, "running", json.dumps(details or {}), iso_now()),
            )
        return job_id

    def finish_job(self, job_id: str, status: str, details: dict[str, Any] | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status = ?, details_json = ?, finished_at = ? WHERE id = ?",
                (status, json.dumps(details or {}, ensure_ascii=False), iso_now(), job_id),
            )

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                (key,),
            ).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, value, iso_now()),
            )
