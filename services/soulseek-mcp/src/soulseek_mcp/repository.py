from __future__ import annotations

from typing import Any

from mcp_common.store import AtomicJsonStore

from .models import AlbumCandidate, DownloadBatch


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


class BatchRepository:
    """Remembers which files belong to one queued album.

    slskd has no batch of its own — it queues per user and file — so the only
    place the membership of an album can live is here. Without it a finished
    download cannot be told apart from any other transfer of the same peer,
    and the folder the operator asked for cannot be assembled.
    """

    def __init__(self, path):
        self.store = AtomicJsonStore(path, default={})

    def save(self, batch: DownloadBatch) -> DownloadBatch:
        current = self.store.read()
        current[batch.batch_id] = batch.model_dump(mode="json")
        if len(current) > 500:
            current = dict(list(current.items())[-500:])
        self.store.write(current)
        return batch

    def get(self, batch_id: str) -> DownloadBatch | None:
        raw = self.store.read().get(batch_id)
        return DownloadBatch.model_validate(raw) if isinstance(raw, dict) else None

    def update(self, batch_id: str, **fields: Any) -> DownloadBatch | None:
        batch = self.get(batch_id)
        if batch is None:
            return None
        return self.save(batch.model_copy(update=fields))
