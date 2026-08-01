from mcp_lib.album_matcher import build_album_candidates


def test_groups_multidisc_album_and_keeps_sidecars() -> None:
    payload = {
        "id": "search-1",
        "responses": [
            {
                "username": "lossless-user",
                "hasFreeUploadSlot": True,
                "uploadSpeed": 2_000_000,
                "queueLength": 0,
                "files": [
                    {"filename": r"Music\Massive Attack\Mezzanine\CD1\01 Angel.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\CD1\02 Risingson.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\CD1\03 Teardrop.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\CD2\01 Bonus.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\CD2\02 Bonus.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\CD2\03 Bonus.flac", "size": 100},
                    {"filename": r"Music\Massive Attack\Mezzanine\cover.jpg", "size": 20},
                    {"filename": r"Music\Massive Attack\Mezzanine\runme.exe", "size": 20},
                ],
            },
            {
                "username": "mp3-user",
                "hasFreeUploadSlot": False,
                "uploadSpeed": 200_000,
                "queueLength": 12,
                "files": [
                    {"filename": rf"Share\Massive Attack - Mezzanine\{i:02d} Track.mp3", "size": 80}
                    for i in range(1, 7)
                ],
            },
        ],
    }

    candidates = build_album_candidates(
        payload=payload,
        artist="Massive Attack",
        album="Mezzanine",
        search_id="search-1",
        preferred_formats=["flac", "mp3"],
        minimum_tracks=4,
    )

    assert len(candidates) == 2
    best = candidates[0]
    assert best.username == "lossless-user"
    assert best.folder.endswith("Massive Attack/Mezzanine")
    assert best.disc_count == 2
    assert best.audio_file_count == 6
    assert best.total_file_count == 7
    assert best.formats == ["flac"]
    assert not any(file.filename.endswith(".exe") for file in best.files)


def test_rejects_incomplete_folder() -> None:
    payload = {
        "responses": [
            {
                "username": "user",
                "files": [
                    {"filename": r"Artist\Album\01.flac", "size": 1},
                    {"filename": r"Artist\Album\02.flac", "size": 1},
                ],
            }
        ]
    }
    candidates = build_album_candidates(
        payload=payload,
        artist="Artist",
        album="Album",
        search_id="x",
        preferred_formats=["flac"],
        minimum_tracks=4,
    )
    assert candidates == []
