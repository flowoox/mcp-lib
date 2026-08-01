from pathlib import Path

from mcp_lib.config import SoulseekSettings, TraxxSettings


FORBIDDEN_APPLICATION_IMPORTS = (
    "control_plane",
    "pipeline",
    "spotify",
    "state",
)


def test_mcp_servers_do_not_import_product_modules() -> None:
    package_root = Path(__file__).parents[1] / "src" / "mcp_lib"
    for filename in ("mcp_soulseek.py", "mcp_traxx.py"):
        source = (package_root / filename).read_text(encoding="utf-8")
        for module in FORBIDDEN_APPLICATION_IMPORTS:
            assert f"from .{module}" not in source
            assert f"import mcp_lib.{module}" not in source


def test_service_settings_are_independent(tmp_path: Path) -> None:
    soulseek = SoulseekSettings(
        downloads_dir=tmp_path / "downloads",
        state_db=tmp_path / "soulseek.sqlite3",
        slskd_url="http://slskd:5030/",
    )
    traxx = TraxxSettings(
        downloads_dir=tmp_path / "downloads",
        traxx_url="https://traxx.example/",
    )

    assert soulseek.mcp_port == 8081
    assert soulseek.slskd_url == "http://slskd:5030"
    assert traxx.mcp_port == 8082
    assert traxx.traxx_url == "https://traxx.example"
    assert not hasattr(soulseek, "traxx_token")
    assert not hasattr(traxx, "slskd_api_key")
