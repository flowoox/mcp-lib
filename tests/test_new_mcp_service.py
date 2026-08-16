from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_scaffolder_creates_renamed_service(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "new-mcp-service.py"
    target = tmp_path / "proxmox-mcp"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--name",
            "proxmox",
            "--contract",
            "flowoox.proxmox",
            "--output",
            str(target),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Created" in result.stdout
    assert (target / "src" / "proxmox_mcp" / "server.py").is_file()
    assert not (target / "src" / "example_mcp").exists()

    pyproject = (target / "pyproject.toml").read_text(encoding="utf-8")
    contract = (target / "src" / "proxmox_mcp" / "contract.py").read_text(encoding="utf-8")
    server = (target / "src" / "proxmox_mcp" / "server.py").read_text(encoding="utf-8")

    assert "flowoox-mcp-proxmox" in pyproject
    assert 'mcp-proxmox = "proxmox_mcp.server:main"' in pyproject
    assert "flowoox.proxmox" in contract
    assert "example_mcp" not in pyproject
    assert "Flowoox MCP Proxmox" in server


def test_scaffolder_refuses_existing_target(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "new-mcp-service.py"
    target = tmp_path / "existing"
    target.mkdir()

    result = subprocess.run(
        [sys.executable, str(script), "--name", "proxmox", "--output", str(target)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "target already exists" in (result.stderr + result.stdout)
