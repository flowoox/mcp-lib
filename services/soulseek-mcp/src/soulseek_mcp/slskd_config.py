from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class SlskdConfigurationError(ValueError):
    pass


def _mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        value = {}
        parent[key] = value
    return value


class SlskdConfigurationWriter:
    """Atomically maintain the watched slskd YAML file.

    The file necessarily contains the Soulseek password because slskd itself
    consumes it. It is written with mode 0600 and is never returned by an MCP
    tool.
    """

    def __init__(self, path: Path):
        self.path = path

    def write(
        self,
        *,
        soulseek_username: str,
        soulseek_password: str,
        api_key: str,
        web_username: str,
        web_password: str,
        listen_port: int = 50300,
    ) -> None:
        if not soulseek_username.strip() or not soulseek_password:
            raise SlskdConfigurationError(
                "Soulseek username and password are required"
            )
        if not 16 <= len(api_key) <= 255:
            raise SlskdConfigurationError(
                "slskd API key must contain between 16 and 255 characters"
            )
        if not web_username.strip() or not web_password:
            raise SlskdConfigurationError(
                "slskd web username and password are required"
            )

        config: dict[str, Any] = {}
        if self.path.exists():
            try:
                parsed = yaml.safe_load(self.path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    config = parsed
            except (OSError, yaml.YAMLError):
                config = {}

        soulseek = _mapping(config, "soulseek")
        soulseek.update(
            {
                "username": soulseek_username.strip(),
                "password": soulseek_password,
                "listen_port": int(listen_port),
            }
        )

        directories = _mapping(config, "directories")
        directories.update({"downloads": "/downloads", "incomplete": "/incomplete"})

        shares = _mapping(config, "shares")
        share_directories = shares.get("directories")
        if not isinstance(share_directories, list):
            share_directories = []
        if "/music" not in share_directories:
            share_directories.append("/music")
        shares["directories"] = share_directories

        web = _mapping(config, "web")
        web["port"] = 5030
        authentication = _mapping(web, "authentication")
        authentication.update(
            {
                "disabled": False,
                "username": web_username.strip(),
                "password": web_password,
            }
        )
        api_keys = _mapping(authentication, "api_keys")
        api_keys["release_radar"] = {
            "key": api_key,
            "role": "Administrator",
            "cidr": "0.0.0.0/0,::/0",
        }

        config["remote_configuration"] = True
        config["remote_file_management"] = False

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)
