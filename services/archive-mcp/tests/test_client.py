import hashlib
from pathlib import Path

import httpx
import pytest

from archive_mcp.client import (
    ArchiveClient,
    ArchiveError,
    deterministic_batch_id,
    local_file_name,
    sanitize_destination,
)
from archive_mcp.config import RuntimeConfig
from archive_mcp.models import ArchiveFile
from archive_mcp.repository import BatchRepository

CC_BY = "https://creativecommons.org/licenses/by/4.0/"


def make_client(tmp_path: Path) -> ArchiveClient:
    return ArchiveClient(
        RuntimeConfig(),
        batches=BatchRepository(tmp_path / "batches.json"),
        downloads_dir=tmp_path / "downloads",
    )


def test_missing_item_answers_http_200_with_an_empty_object(tmp_path: Path) -> None:
    """Measured against the live API: ``/metadata/does-not-exist`` returns
    **200 with ``{}``**, not 404. Trusting the status code would turn every
    typo into a candidate with no files."""
    client = make_client(tmp_path)
    candidate, reason = client.build_candidate(
        identifier="does-not-exist",
        metadata={},
        artist="A",
        album="B",
        search_id="s",
        expected_track_count=None,
        lossless_only=False,
        minimum_lossy_bitrate_kbps=128,
    )
    assert candidate is None
    assert "existiert nicht" in reason


def test_item_without_a_readable_license_never_becomes_a_candidate(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    candidate, reason = client.build_candidate(
        identifier="x",
        metadata={
            "metadata": {"title": "Some Album", "creator": "Some Artist"},
            "files": [{"name": "01.flac", "format": "Flac", "source": "original", "track": "1"}],
        },
        artist="Some Artist",
        album="Some Album",
        search_id="s",
        expected_track_count=None,
        lossless_only=False,
        minimum_lossy_bitrate_kbps=128,
    )
    assert candidate is None
    assert "Lizenz" in reason


def test_licensed_item_becomes_a_candidate_carrying_its_license(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    candidate, _ = client.build_candidate(
        identifier="cz-album",
        metadata={
            "metadata": {
                "title": "O Great Queen Electric",
                "creator": "Chris Zabriskie",
                "licenseurl": CC_BY,
                "collection": ["opensource_audio", "community"],
            },
            "files": [
                {"name": "01 - Time Life.flac", "format": "Flac", "source": "original",
                 "track": "1/9", "size": "553615", "md5": "abc", "length": "25.59"},
                {"name": "01 - Time Life.mp3", "format": "VBR MP3", "source": "derivative",
                 "track": "1/9", "size": "302120", "length": "25.63"},
            ],
        },
        artist="Chris Zabriskie",
        album="O Great Queen Electric",
        search_id="s",
        expected_track_count=1,
        lossless_only=False,
        minimum_lossy_bitrate_kbps=128,
    )
    assert candidate is not None
    assert candidate.license_url == CC_BY
    assert candidate.license_label == "CC BY 4.0"
    assert candidate.rights_basis == "licensed"
    assert candidate.collections == ["opensource_audio", "community"]
    # The mp3 derivative of the same track must not appear a second time.
    assert [file.name for file in candidate.files] == ["01 - Time Life.flac"]


def test_batch_id_is_the_same_for_one_recommendation(tmp_path: Path) -> None:
    """Re-queuing after a restart must find the existing batch rather than
    fetching the album twice into the same folder."""
    first = deterministic_batch_id("cand", "rec-1")
    assert first == deterministic_batch_id("cand", "rec-1")
    assert first != deterministic_batch_id("cand", "rec-2")


@pytest.mark.parametrize("value", ["", "/absolute", "../escape", "a/../../b", "."])
def test_destination_cannot_escape_the_downloads_volume(value: str) -> None:
    with pytest.raises(ValueError):
        sanitize_destination(value)


def test_destination_keeps_the_requested_shape() -> None:
    assert sanitize_destination("library/profile/Artist/Album") == (
        "library/profile/Artist/Album"
    )


def test_files_from_a_subfolder_are_flattened_without_overwriting(tmp_path: Path) -> None:
    """Item files may sit in a subdirectory. They all land in one destination
    folder, so two files whose names collide after sanitizing must not become
    one file — that would silently drop a track."""
    taken: set[str] = set()
    first = ArchiveFile(name="cd1/01 Song.flac", extension="flac", track=1, disc=1)
    second = ArchiveFile(name="cd2/01 Song.flac", extension="flac", track=1, disc=2)
    name_a = local_file_name(first, taken)
    taken.add(name_a.casefold())
    name_b = local_file_name(second, taken)
    assert name_a != name_b
    assert name_a.endswith(".flac") and name_b.endswith(".flac")


def test_archive_filename_oddities_survive_sanitizing() -> None:
    """The Archive replaces characters it cannot store — a title's ``?``
    becomes ``¿``. The name still has to keep its extension and its leading
    track number, because the importer reads the track number off the name."""
    file = ArchiveFile(
        name="Chris Zabriskie - O Great Queen Electric, What Do You Have Waiting for Me¿ - 01 - Time Life.flac",
        extension="flac",
        track=1,
    )
    name = local_file_name(file, set())
    assert name.endswith(".flac")
    assert "01" in name


async def test_download_rejects_a_file_whose_md5_does_not_match(tmp_path: Path) -> None:
    """The Archive publishes an md5 per file — the one thing a peer network
    cannot offer. A truncated or mis-served transfer has to fail here, not
    surface as a corrupt track after the import."""
    client = make_client(tmp_path)
    target = tmp_path / "downloads"
    target.mkdir(parents=True, exist_ok=True)
    body = b"not the expected bytes"

    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    async with httpx.AsyncClient(transport=transport) as http:
        file = ArchiveFile(name="01.flac", extension="flac", md5="0" * 32, size=len(body))
        with pytest.raises(ArchiveError, match="md5"):
            await client.fetch_file(http, "item", file, target / "01.flac")
    # Nothing half-written may be left behind for the importer to find.
    assert not (target / "01.flac").exists()
    assert not (target / "01.flac.part").exists()


async def test_download_rejects_a_short_read(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    target = tmp_path / "downloads"
    target.mkdir(parents=True, exist_ok=True)
    body = b"12345"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    async with httpx.AsyncClient(transport=transport) as http:
        file = ArchiveFile(name="01.flac", extension="flac", size=999)
        with pytest.raises(ArchiveError, match="Bytes"):
            await client.fetch_file(http, "item", file, target / "01.flac")


async def test_verified_download_lands_under_the_requested_name(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    target = tmp_path / "downloads"
    target.mkdir(parents=True, exist_ok=True)
    body = b"fLaC and then some bytes"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    async with httpx.AsyncClient(transport=transport) as http:
        file = ArchiveFile(
            name="01.flac",
            extension="flac",
            size=len(body),
            md5=hashlib.md5(body).hexdigest(),
        )
        written = await client.fetch_file(http, "item", file, target / "01.flac")
    assert written == len(body)
    assert (target / "01.flac").read_bytes() == body


def test_query_ladder_starts_fielded_and_only_then_widens(tmp_path: Path) -> None:
    """Measured on the live index: the fielded query returned 2 hits for a
    known album while the same words as free text returned 10, eight of them
    podcasts. Widening first would bury the real item."""
    client = make_client(tmp_path)
    ladder = client.query_ladder("Chris Zabriskie", "Cylinders", None)
    assert ladder[0].startswith("mediatype:audio AND creator:")
    assert "title:" in ladder[0]
    assert all(query.startswith("mediatype:audio") for query in ladder)


def test_explicit_search_text_replaces_the_ladder(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    assert client.query_ladder("A", "B", "custom terms") == [
        "mediatype:audio AND (custom terms)"
    ]
