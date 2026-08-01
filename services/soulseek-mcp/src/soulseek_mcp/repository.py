from __future__ import annotations

from mcp_common.store import AtomicJsonStore

from .models import AlbumCandidate


class CandidateRepository:
    def __init__(self, path):
        self.store = AtomicJsonStore(path, default={})

    def save_many(self, candidates: list[AlbumCandidate]) -> None:
        current = self.store.read()
        for candidate in candidates:
            current[candidate.candidate_id] = candidate.model_dump(mode="json")
        # Keep the most recently written candidates while preventing unbounded growth.
        if len(current) > 1000:
            current = dict(list(current.items())[-1000:])
        self.store.write(current)

    def get(self, candidate_id: str) -> AlbumCandidate | None:
        raw = self.store.read().get(candidate_id)
        return AlbumCandidate.model_validate(raw) if isinstance(raw, dict) else None
