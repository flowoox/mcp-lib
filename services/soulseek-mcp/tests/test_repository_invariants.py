from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_repository_contains_only_permanent_workflows() -> None:
    workflows = {path.name for path in (ROOT / ".github" / "workflows").glob("*.yml")}
    assert workflows == {
        "ad-mcp.yml",
        "ci.yml",
        "publish-soulseek.yml",
        "publish-traxx.yml",
    }


def test_both_service_images_are_versioned_and_health_checked() -> None:
    for service, port in (("soulseek-mcp", "8081"), ("traxx-mcp", "8082")):
        dockerfile = (ROOT / "services" / service / "Dockerfile").read_text(
            encoding="utf-8"
        )
        assert "ARG VERSION=0.3.1" in dockerfile
        assert "HEALTHCHECK" in dockerfile
        assert f"127.0.0.1', {port}" in dockerfile
