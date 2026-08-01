from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import AlbumCandidate
from .utils import iso_now


class CandidateStore:
    """Small service-local cache for Soulseek album-folder candidates."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS album_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    candidate_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def save(self, candidate: AlbumCandidate) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO album_candidates(candidate_id, candidate_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(candidate_id) DO UPDATE SET
                    candidate_json=excluded.candidate_json,
                    updated_at=excluded.updated_at
                """,
                (
                    candidate.candidate_id,
                    candidate.model_dump_json(),
                    iso_now(),
                ),
            )

    def get(self, candidate_id: str) -> AlbumCandidate | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT candidate_json FROM album_candidates WHERE candidate_id = ?",
                (candidate_id,),
            ).fetchone()
        if not row:
            return None
        return AlbumCandidate.model_validate_json(str(row["candidate_json"]))
