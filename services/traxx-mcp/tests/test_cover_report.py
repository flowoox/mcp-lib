"""An import that produced no sleeve has to say so."""

from __future__ import annotations

from pathlib import Path

from traxx_mcp.client import describe_cover


def test_a_missing_cover_is_named_rather_than_passed_over() -> None:
    report = describe_cover(None, "")

    # Measured on the live library: an album imported from a folder without a
    # picture and without a cover address showed as a blank tile, and nothing
    # anywhere said why.
    assert report["ok"] is False
    assert "Kein Cover" in report["warning"]
    assert report["source"] == "keine"


def test_a_picture_in_the_folder_is_the_better_source() -> None:
    report = describe_cover(Path("/downloads/Album/cover.jpg"), "storage/artwork/x.jpg")
    assert report["ok"] is True
    assert report["source"] == "Datei im Ordner"
    assert not report["warning"]


def test_an_external_address_still_counts_as_a_cover() -> None:
    report = describe_cover(None, "https://i.scdn.co/image/abc")
    assert report["ok"] is True
    assert report["source"] == "externe Adresse"
    assert not report["warning"]
