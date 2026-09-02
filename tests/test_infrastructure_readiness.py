from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_infrastructure_readiness import (
    ReadinessError,
    parse_root_ci_matrix,
    validate_repository,
)


def test_parse_root_ci_matrix_extracts_service_distribution_pairs() -> None:
    matrix = parse_root_ci_matrix(
        """
        include:
          - service: ad-mcp
            distribution: flowoox-mcp-ad
          - service: network-mcp
            distribution: flowoox-mcp-network
        """
    )
    assert matrix == {
        "ad-mcp": "flowoox-mcp-ad",
        "network-mcp": "flowoox-mcp-network",
    }


def test_parse_root_ci_matrix_rejects_duplicate_service() -> None:
    with pytest.raises(ReadinessError, match="duplicate root CI matrix service"):
        parse_root_ci_matrix(
            """
            - service: ad-mcp
              distribution: flowoox-mcp-ad
            - service: ad-mcp
              distribution: flowoox-mcp-ad
            """
        )


def test_repository_readiness_manifest_matches_current_repository() -> None:
    assert validate_repository() == []


def test_readiness_detects_service_removed_from_root_matrix(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    (tmp_path / "docs" / "infrastructure").mkdir(parents=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "services" / "demo-mcp" / "src").mkdir(parents=True)
    (tmp_path / "services" / "demo-mcp" / "tests").mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "services": [
            {
                "service": "demo-mcp",
                "distribution": "flowoox-mcp-demo",
                "dedicated_workflow": None,
                "security_profile": "read-only",
            }
        ],
    }
    (tmp_path / "docs" / "infrastructure" / "service-readiness.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "matrix:\n  include: []\n", encoding="utf-8"
    )
    (tmp_path / "services" / "demo-mcp" / "README.md").write_text("# Demo\n", encoding="utf-8")
    (tmp_path / "services" / "demo-mcp" / ".env.example").write_text("DEMO=false\n", encoding="utf-8")
    (tmp_path / "services" / "demo-mcp" / "pyproject.toml").write_text(
        """
[project]
name = "flowoox-mcp-demo"
version = "0.1.0"
[project.scripts]
mcp-demo = "demo_mcp.server:main"
""".strip(),
        encoding="utf-8",
    )
    errors = validate_repository(tmp_path)
    assert "demo-mcp: missing from root CI python matrix" in errors
    assert source_root.exists()
