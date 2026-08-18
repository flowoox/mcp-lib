from pathlib import Path

from archive_mcp.models import AlbumCandidate, ArchiveFile, DownloadBatch
from archive_mcp.repository import BatchRepository, CandidateRepository


def make_batch(batch_id: str = "b1") -> DownloadBatch:
    return DownloadBatch(
        batch_id=batch_id,
        candidate_id="c1",
        identifier="item",
        filenames=["01.flac", "02.flac"],
        destination="library/p/Artist/Album",
        file_states={"01.flac": "queued", "02.flac": "queued"},
    )


def test_batch_survives_a_write_and_read_round_trip(tmp_path: Path) -> None:
    repository = BatchRepository(tmp_path / "batches.json")
    repository.save(make_batch())
    stored = repository.get("b1")
    assert stored is not None
    assert stored.filenames == ["01.flac", "02.flac"]
    assert stored.destination == "library/p/Artist/Album"


def test_update_keeps_the_fields_it_was_not_given(tmp_path: Path) -> None:
    """Progress is written on every finished file. An update that dropped the
    destination would leave the poll unable to say where the album went."""
    repository = BatchRepository(tmp_path / "batches.json")
    repository.save(make_batch())
    repository.update("b1", state="completed", bytes_done=42)
    stored = repository.get("b1")
    assert stored is not None
    assert stored.state == "completed"
    assert stored.bytes_done == 42
    assert stored.destination == "library/p/Artist/Album"
    assert stored.filenames == ["01.flac", "02.flac"]


def test_updating_an_unknown_batch_reports_it_instead_of_creating_one(tmp_path: Path) -> None:
    repository = BatchRepository(tmp_path / "batches.json")
    assert repository.update("nope", state="completed") is None
    assert repository.get("nope") is None


def test_candidates_round_trip_with_their_license(tmp_path: Path) -> None:
    repository = CandidateRepository(tmp_path / "candidates.json")
    candidate = AlbumCandidate(
        candidate_id="c1",
        identifier="item",
        folder="item",
        artist="Artist",
        album="Album",
        files=[ArchiveFile(name="01.flac", extension="flac", track=1)],
        audio_file_count=1,
        total_file_count=3,
        license_url="https://creativecommons.org/licenses/by/4.0/",
        license_label="CC BY 4.0",
        rights_basis="licensed",
    )
    repository.save_many([candidate])
    stored = repository.get("c1")
    assert stored is not None
    # The licence has to survive: queue_album_folder uses it as the rights
    # reference when the caller supplies none.
    assert stored.license_url == "https://creativecommons.org/licenses/by/4.0/"
    assert stored.rights_basis == "licensed"


def test_list_of_batches_is_readable_for_the_downloads_overview(tmp_path: Path) -> None:
    repository = BatchRepository(tmp_path / "batches.json")
    repository.save(make_batch("b1"))
    repository.save(make_batch("b2"))
    assert {batch.batch_id for batch in repository.all()} == {"b1", "b2"}
