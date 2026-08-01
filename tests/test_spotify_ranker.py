from mcp_lib.models import SpotifyAlbumCandidate
from mcp_lib.spotify import rank_album_candidates


def album(identifier: str, name: str, score: float, album_type: str = "album") -> SpotifyAlbumCandidate:
    return SpotifyAlbumCandidate(
        spotify_id=identifier,
        name=name,
        artists=[{"id": "artist-1", "name": "Artist"}],
        release_date="2025-01-01",
        album_type=album_type,
        total_tracks=10,
        score=score,
        source_reasons=["top artist"],
    )


def test_ranker_excludes_known_and_singles() -> None:
    ranked = rank_album_candidates(
        [
            album("known", "Known", 200),
            album("single", "Single", 190, album_type="single"),
            album("new-high", "New High", 180),
            album("new-low", "New Low", 120),
        ],
        excluded_ids={"known"},
        limit=5,
    )
    assert [item.spotify_id for item in ranked] == ["new-high", "new-low"]


def test_ranker_deduplicates_by_spotify_id() -> None:
    ranked = rank_album_candidates(
        [album("same", "Album", 50), album("same", "Album", 90)],
        limit=5,
    )
    assert len(ranked) == 1
    assert ranked[0].score >= 90
