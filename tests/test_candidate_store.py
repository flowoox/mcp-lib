from pathlib import Path

from mcp_lib.candidate_store import CandidateStore
from mcp_lib.models import AlbumCandidate, RemoteFile


def candidate() -> AlbumCandidate:
    return AlbumCandidate(
        candidate_id="candidate-1",
        search_id="search-1",
        username="peer",
        folder="Artist\\Album",
        artist="Artist",
        album="Album",
        files=[RemoteFile(filename="Artist\\Album\\01.flac", size=123, extension="flac")],
        audio_file_count=1,
        total_file_count=1,
        formats=["flac"],
    )


def test_candidate_store_roundtrip(tmp_path: Path) -> None:
    store = CandidateStore(tmp_path / "state.sqlite3")
    expected = candidate()

    store.save(expected)
    actual = store.get(expected.candidate_id)

    assert actual == expected


def test_candidate_store_updates_existing_candidate(tmp_path: Path) -> None:
    store = CandidateStore(tmp_path / "state.sqlite3")
    original = candidate()
    store.save(original)

    updated = original.model_copy(update={"score": 97.5})
    store.save(updated)

    assert store.get(original.candidate_id) == updated
