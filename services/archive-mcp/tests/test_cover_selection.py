"""An album has to arrive with its sleeve, or the library shows a blank tile."""

from __future__ import annotations

from archive_mcp.matcher import select_cover_file


def test_the_real_sleeve_beats_the_generated_thumbnail() -> None:
    records = [
        {"name": "__ia_thumb.jpg", "size": "4210", "source": "derivative"},
        {"name": "cz-ogreatqueenelectric_itemimage.jpg", "size": "9100",
         "source": "derivative"},
        {"name": "front.jpg", "size": "553615", "source": "original"},
        {"name": "01 Time Life.flac", "size": "33962428", "source": "original"},
    ]

    chosen = select_cover_file(records)

    assert chosen is not None
    assert chosen["name"] == "front.jpg"


def test_a_generated_thumbnail_is_better_than_nothing() -> None:
    # An item with no uploaded artwork still has the Archive's own thumbnail,
    # and a smudge is more use than a blank tile.
    records = [
        {"name": "__ia_thumb.jpg", "size": "4210", "source": "derivative"},
        {"name": "01 Track.flac", "size": "1", "source": "original"},
    ]

    chosen = select_cover_file(records)

    assert chosen is not None and chosen["name"] == "__ia_thumb.jpg"


def test_the_largest_original_wins_among_equals() -> None:
    records = [
        {"name": "back.png", "size": "120000", "source": "original"},
        {"name": "front.png", "size": "800000", "source": "original"},
    ]
    assert select_cover_file(records)["name"] == "front.png"


def test_an_item_without_pictures_says_so() -> None:
    assert select_cover_file([{"name": "01.flac", "size": "1", "source": "original"}]) is None
    assert select_cover_file([]) is None
