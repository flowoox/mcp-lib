from pathlib import Path

import pytest
import yaml

from soulseek_mcp.slskd_config import (
    SlskdConfigurationError,
    SlskdConfigurationWriter,
)


def test_writes_watched_slskd_yaml_with_secure_mode(tmp_path: Path) -> None:
    path = tmp_path / "slskd.yml"
    SlskdConfigurationWriter(path).write(
        soulseek_username="soul-user",
        soulseek_password="soul-password",
        api_key="x" * 32,
        web_username="admin",
        web_password="web-password",
    )
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert config["soulseek"]["username"] == "soul-user"
    assert config["directories"]["downloads"] == "/downloads"
    assert config["web"]["authentication"]["api_keys"]["release_radar"] == {
        "key": "x" * 32,
        "role": "Administrator",
        "cidr": "0.0.0.0/0,::/0",
    }
    assert config["remote_configuration"] is True
    assert path.stat().st_mode & 0o777 == 0o600


def test_rejects_short_api_key(tmp_path: Path) -> None:
    with pytest.raises(SlskdConfigurationError, match="between 16 and 255"):
        SlskdConfigurationWriter(tmp_path / "slskd.yml").write(
            soulseek_username="user",
            soulseek_password="password",
            api_key="short",
            web_username="admin",
            web_password="web-password",
        )
