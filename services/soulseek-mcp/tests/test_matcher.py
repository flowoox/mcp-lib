from soulseek_mcp.matcher import build_album_candidates


def test_groups_multi_disc_album_and_blocks_executables():
    payload = {
        "responses": [{
            "username": "peer",
            "hasFreeUploadSlot": True,
            "uploadSpeed": 1000000,
            "files": [
                {"filename": r"Artist\\Album\\CD1\\01.flac", "size": 10},
                {"filename": r"Artist\\Album\\CD1\\02.flac", "size": 10},
                {"filename": r"Artist\\Album\\CD2\\03.flac", "size": 10},
                {"filename": r"Artist\\Album\\CD2\\04.flac", "size": 10},
                {"filename": r"Artist\\Album\\cover.jpg", "size": 2},
                {"filename": r"Artist\\Album\\evil.exe", "size": 2},
            ],
        }]
    }
    candidates = build_album_candidates(payload=payload, artist="Artist", album="Album", search_id="s1", preferred_formats=["flac", "mp3"], minimum_tracks=4)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.disc_count == 2
    assert candidate.audio_file_count == 4
    assert candidate.total_file_count == 5
    assert all(not item.filename.endswith(".exe") for item in candidate.files)
