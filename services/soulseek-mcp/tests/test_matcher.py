from soulseek_mcp.matcher import build_album_candidates


def files_payload(files):
    return {"responses": [{"username": "peer", "files": files}]}


def test_groups_multi_disc_album_and_blocks_executables():
    payload = files_payload(
        [
            {"filename": r"Artist\Album\CD1\01.flac", "size": 10},
            {"filename": r"Artist\Album\CD1\02.flac", "size": 10},
            {"filename": r"Artist\Album\CD2\03.flac", "size": 10},
            {"filename": r"Artist\Album\CD2\04.flac", "size": 10},
            {"filename": r"Artist\Album\cover.jpg", "size": 2},
            {"filename": r"Artist\Album\evil.exe", "size": 2},
        ]
    )
    candidates, _rejected = build_album_candidates(
        payload=payload,
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["flac", "wav"],
        minimum_tracks=4,
    )
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.disc_count == 2
    assert candidate.audio_file_count == 4
    assert candidate.total_file_count == 5
    assert candidate.formats == ["flac"]
    assert all(not item.filename.endswith(".exe") for item in candidate.files)


def test_rejects_mp3_by_default_even_at_320_kbps():
    payload = files_payload(
        [
            {
                "filename": rf"Artist\Album\{number:02}.mp3",
                "size": 10,
                "bitRate": 320,
            }
            for number in range(1, 5)
        ]
    )
    assert (
        build_album_candidates(
            payload=payload,
            artist="Artist",
            album="Album",
            search_id="s1",
            preferred_formats=["flac", "mp3"],
            minimum_tracks=4,
        )[0]
        == []
    )


def test_optional_lossy_fallback_requires_320_kbps():
    payload_320 = files_payload(
        [
            {
                "filename": rf"Artist\Album\{number:02}.mp3",
                "size": 10,
                "bitRate": 320000,
            }
            for number in range(1, 5)
        ]
    )
    candidates, _rejected = build_album_candidates(
        payload=payload_320,
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["mp3"],
        minimum_tracks=4,
        lossless_only=False,
        minimum_lossy_bitrate_kbps=320,
    )
    assert len(candidates) == 1
    assert candidates[0].formats == ["mp3"]

    payload_256 = files_payload(
        [
            {
                "filename": rf"Artist\Album\{number:02}.mp3",
                "size": 10,
                "bitRate": 256,
            }
            for number in range(1, 5)
        ]
    )
    assert (
        build_album_candidates(
            payload=payload_256,
            artist="Artist",
            album="Album",
            search_id="s1",
            preferred_formats=["mp3"],
            minimum_tracks=4,
            lossless_only=False,
            minimum_lossy_bitrate_kbps=320,
        )[0]
        == []
    )


def test_drops_lossy_duplicate_when_lossless_track_exists():
    files = []
    for number in range(1, 5):
        files.extend(
            [
                {"filename": rf"Artist\Album\{number:02}.flac", "size": 100},
                {
                    "filename": rf"Artist\Album\{number:02}.mp3",
                    "size": 10,
                    "bitRate": 128,
                },
            ]
        )
    candidates, _rejected = build_album_candidates(
        payload=files_payload(files),
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["flac"],
        minimum_tracks=4,
    )
    assert len(candidates) == 1
    assert candidates[0].formats == ["flac"]
    assert all(item.extension != "mp3" for item in candidates[0].files)


def test_rejects_album_with_unique_low_quality_track():
    files = [
        {"filename": rf"Artist\Album\{number:02}.flac", "size": 100}
        for number in range(1, 4)
    ]
    files.append(
        {"filename": r"Artist\Album\04.mp3", "size": 10, "bitRate": 128}
    )
    assert (
        build_album_candidates(
            payload=files_payload(files),
            artist="Artist",
            album="Album",
            search_id="s1",
            preferred_formats=["flac"],
            minimum_tracks=4,
        )[0]
        == []
    )


def test_expected_track_count_rejects_incomplete_and_wrong_edition():
    exact = files_payload(
        [
            {"filename": rf"Artist\Album\{number:02}.flac", "size": 100}
            for number in range(1, 11)
        ]
    )
    candidates, _rejected = build_album_candidates(
        payload=exact,
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["flac"],
        minimum_tracks=4,
        expected_track_count=10,
    )
    assert len(candidates) == 1
    assert candidates[0].audio_file_count == 10
    assert "track count matches expected: 10" in candidates[0].score_reasons

    for actual in (9, 11):
        payload = files_payload(
            [
                {"filename": rf"Artist\Album\{number:02}.flac", "size": 100}
                for number in range(1, actual + 1)
            ]
        )
        accepted, rejected = build_album_candidates(
            payload=payload,
            artist="Artist",
            album="Album",
            search_id="s1",
            preferred_formats=["flac"],
            minimum_tracks=4,
            expected_track_count=10,
        )
        assert accepted == []
        # The near miss is reported rather than dropped silently.
        assert rejected and f"{actual} statt der erwarteten 10" in rejected[0]["reason"]


def test_rejected_folders_report_the_quality_they_do_offer() -> None:
    payload = files_payload(
        [
            {"filename": rf"Artist\Album\{number:02}.mp3", "size": 100, "bitRate": 192}
            for number in range(1, 11)
        ]
    )

    accepted, rejected = build_album_candidates(
        payload=payload,
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["flac"],
        minimum_tracks=4,
        lossless_only=True,
    )

    assert accepted == []
    # "Nothing found" and "found, but lossy" are different answers.
    entry = rejected[0]
    assert entry["formats"] == {"mp3": 10}
    assert entry["audio_file_count"] == 10
    assert entry["max_bitrate_kbps"] == 192
    assert "nicht verlustfrei" in entry["reason"]


def test_lowering_the_gate_accepts_what_was_rejected() -> None:
    payload = files_payload(
        [
            {"filename": rf"Artist\Album\{number:02}.mp3", "size": 100, "bitRate": 192}
            for number in range(1, 11)
        ]
    )

    accepted, _ = build_album_candidates(
        payload=payload,
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["mp3"],
        minimum_tracks=4,
        lossless_only=False,
        minimum_lossy_bitrate_kbps=192,
    )

    assert len(accepted) == 1
    assert accepted[0].formats == ["mp3"]


def test_prefers_one_lossless_variant_per_track_before_count_validation() -> None:
    files = []
    for number in range(1, 5):
        files.extend(
            [
                {"filename": rf"Artist\Album\{number:02}.wav", "size": 200},
                {"filename": rf"Artist\Album\{number:02}.flac", "size": 100},
            ]
        )
    candidates, _rejected = build_album_candidates(
        payload=files_payload(files),
        artist="Artist",
        album="Album",
        search_id="s1",
        preferred_formats=["flac", "wav"],
        minimum_tracks=4,
        expected_track_count=4,
    )
    assert len(candidates) == 1
    assert candidates[0].audio_file_count == 4
    assert candidates[0].formats == ["flac"]
    assert all(item.extension != "wav" for item in candidates[0].files)
