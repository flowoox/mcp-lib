from mcp_lib.traxx import normalize_genres


def test_normalize_genres_from_bemusic_resources() -> None:
    assert normalize_genres(
        [
            {"id": 1, "name": "Electronic"},
            {"display_name": "Ambient"},
            "Downtempo",
            {"name": "Electronic"},
        ]
    ) == ["Electronic", "Ambient", "Downtempo"]


def test_normalize_genres_uses_local_fallback() -> None:
    assert normalize_genres(None, fallback=["Jazz"]) == ["Jazz"]
    assert normalize_genres([], fallback=["Jazz"]) == ["Jazz"]
