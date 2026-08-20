"""The instance's upload limit, asked before anything is created."""

from __future__ import annotations

from pathlib import Path

import pytest

from traxx_mcp.client import TraxxClient
from traxx_mcp.config import RuntimeConfig


class Limited(TraxxClient):
    def __init__(self, tmp_path: Path, limit: int | None):
        super().__init__(
            RuntimeConfig(base_url="https://traxx.test", token="t"),
            downloads_dir=tmp_path,
        )
        self._limit = limit

    async def upload_limits(self) -> dict[str, int]:
        return {"media": self._limit} if self._limit else {}


def flac(tmp_path: Path, name: str, size: int) -> Path:
    path = tmp_path / name
    path.write_bytes(b"\x00" * size)
    return path


@pytest.mark.asyncio
async def test_files_over_the_limit_are_named_before_anything_is_created(
    tmp_path: Path,
) -> None:
    client = Limited(tmp_path, limit=10_485_760)
    files = [flac(tmp_path, "01.flac", 30_000_000), flac(tmp_path, "02.flac", 1_000)]

    message = await client.check_upload_sizes(files)

    # Measured on the live instance: the limit dropped from 600 MB to 10 MB,
    # every track was refused with 422, and nineteen empty albums were left
    # behind because the album is created before the first upload is tried.
    assert "1 von 2 Dateien" in message
    assert "10 MB" in message
    assert "01.flac" in message
    # It has to say where the setting lives, or it reads as a radar fault.
    assert "Traxx-Seite" in message


@pytest.mark.asyncio
async def test_files_within_the_limit_raise_no_objection(tmp_path: Path) -> None:
    client = Limited(tmp_path, limit=600_000_000)
    files = [flac(tmp_path, "01.flac", 30_000_000)]
    assert await client.check_upload_sizes(files) == ""


@pytest.mark.asyncio
async def test_an_unknown_limit_is_not_treated_as_a_refusal(tmp_path: Path) -> None:
    client = Limited(tmp_path, limit=None)
    files = [flac(tmp_path, "01.flac", 900_000_000)]
    # Not knowing is not the same as knowing it is too big; the upload decides.
    assert await client.check_upload_sizes(files) == ""
