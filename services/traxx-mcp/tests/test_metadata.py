from traxx_mcp.client import normalize_genres


def test_normalize_genres_from_resources():
    assert normalize_genres([{"id": 1, "name": "Rock"}, {"name": "Metal"}]) == ["Rock", "Metal"]


def test_normalize_genres_uses_fallback():
    assert normalize_genres(None, ["Jazz"]) == ["Jazz"]
