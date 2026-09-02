from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs" / "infrastructure" / "service-readiness.json"
ROOT_CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
_MATRIX_PAIR_RE = re.compile(
    r"^[ \t]*-[ \t]+service:[ \t]*([a-z0-9-]+)[ \t]*$\n"
    r"^[ \t]+distribution:[ \t]*([a-z0-9-]+)[ \t]*$",
    re.MULTILINE,
)
_ALLOWED_SECURITY_PROFILES = frozenset({"read-only", "controlled-lifecycle"})


class ReadinessError(RuntimeError):
    pass


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ReadinessError("service-readiness.json schema_version must be 1")
    services = data.get("services")
    if not isinstance(services, list) or not services:
        raise ReadinessError("service-readiness.json must contain a non-empty services list")
    return data


def parse_root_ci_matrix(text: str) -> dict[str, str]:
    pairs = _MATRIX_PAIR_RE.findall(text)
    matrix: dict[str, str] = {}
    for service, distribution in pairs:
        if service in matrix:
            raise ReadinessError(f"duplicate root CI matrix service: {service}")
        matrix[service] = distribution
    return matrix


def _project_metadata(service_dir: Path) -> tuple[str, dict[str, str]]:
    data = tomllib.loads((service_dir / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project", {})
    project_name = project.get("name")
    scripts = project.get("scripts", {})
    if not isinstance(project_name, str) or not project_name:
        raise ReadinessError(f"{service_dir.name}: pyproject project.name is missing")
    if not isinstance(scripts, dict) or not scripts:
        raise ReadinessError(f"{service_dir.name}: at least one project script entrypoint is required")
    return project_name, scripts


def validate_repository(root: Path = ROOT) -> list[str]:
    manifest = load_manifest(root / "docs" / "infrastructure" / "service-readiness.json")
    root_ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    root_matrix = parse_root_ci_matrix(root_ci)
    errors: list[str] = []
    seen_services: set[str] = set()
    seen_distributions: set[str] = set()

    for entry in manifest["services"]:
        if not isinstance(entry, dict):
            errors.append("manifest service entry must be an object")
            continue
        service = entry.get("service")
        distribution = entry.get("distribution")
        workflow = entry.get("dedicated_workflow")
        profile = entry.get("security_profile")
        if not isinstance(service, str) or not re.fullmatch(r"[a-z0-9-]+", service):
            errors.append(f"invalid service name in manifest: {service!r}")
            continue
        if not isinstance(distribution, str) or not distribution.startswith("flowoox-mcp-"):
            errors.append(f"{service}: invalid distribution name {distribution!r}")
            continue
        if service in seen_services:
            errors.append(f"duplicate manifest service: {service}")
        seen_services.add(service)
        if distribution in seen_distributions:
            errors.append(f"duplicate manifest distribution: {distribution}")
        seen_distributions.add(distribution)
        if profile not in _ALLOWED_SECURITY_PROFILES:
            errors.append(f"{service}: unsupported security_profile {profile!r}")

        service_dir = root / "services" / service
        for relative in ("README.md", "pyproject.toml", ".env.example", "src", "tests"):
            if not (service_dir / relative).exists():
                errors.append(f"{service}: required path missing: services/{service}/{relative}")

        if (service_dir / "pyproject.toml").is_file():
            try:
                project_name, scripts = _project_metadata(service_dir)
            except (ReadinessError, tomllib.TOMLDecodeError) as exc:
                errors.append(str(exc))
            else:
                if project_name != distribution:
                    errors.append(
                        f"{service}: manifest distribution {distribution} != pyproject name {project_name}"
                    )
                if not all(isinstance(name, str) and isinstance(target, str) for name, target in scripts.items()):
                    errors.append(f"{service}: project scripts must map strings to strings")

        ci_distribution = root_matrix.get(service)
        if ci_distribution is None:
            errors.append(f"{service}: missing from root CI python matrix")
        elif ci_distribution != distribution:
            errors.append(
                f"{service}: root CI distribution {ci_distribution} != manifest {distribution}"
            )

        if workflow is not None:
            if not isinstance(workflow, str) or not workflow.endswith(".yml"):
                errors.append(f"{service}: invalid dedicated_workflow {workflow!r}")
            else:
                workflow_path = root / ".github" / "workflows" / workflow
                if not workflow_path.is_file():
                    errors.append(f"{service}: declared workflow does not exist: {workflow}")
                else:
                    workflow_text = workflow_path.read_text(encoding="utf-8")
                    for required_marker in (
                        f"services/{service}/",
                        "packages/mcp-common/",
                        "constraints/python312.lock",
                    ):
                        if required_marker not in workflow_text:
                            errors.append(
                                f"{service}: {workflow} missing required marker {required_marker}"
                            )

    non_infra_matrix_services = {"soulseek-mcp", "traxx-mcp", "archive-mcp"}
    unexpected = set(root_matrix) - seen_services - non_infra_matrix_services
    if unexpected:
        errors.append(
            "root CI contains unclassified MCP services: " + ", ".join(sorted(unexpected))
        )
    return errors


def main() -> int:
    errors = validate_repository()
    if errors:
        print("Infrastructure production-readiness policy failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    manifest = load_manifest()
    print(f"Infrastructure production-readiness policy passed for {len(manifest['services'])} services.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
