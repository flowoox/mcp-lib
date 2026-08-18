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
        if len(current) > 1000:
            current = dict(list(current.items())[-1000:])
        self.store.write(current)

    def get(self, candidate_id: str) -> AlbumCandidate | None:
        raw = self.store.read().get(candidate_id)
        return AlbumCandidate.model_validate(raw) if isinstance(raw, dict) else None


class BatchRepository:
    """Remembers one queued item across polls and container restarts.

    The Archive has no queue of its own — a download is a plain HTTP GET this
    connector performs — so the only record that an album was asked for, and
    how far it got, lives here.
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

    def all(self) -> list[DownloadBatch]:
        output: list[DownloadBatch] = []
        for raw in self.store.read().values():
            if isinstance(raw, dict):
                output.append(DownloadBatch.model_validate(raw))
        return output

    def update(self, batch_id: str, **fields: Any) -> DownloadBatch | None:
        batch = self.get(batch_id)
        if batch is None:
            return None
        return self.save(batch.model_copy(update=fields))
