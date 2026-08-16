#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,48}[a-z0-9]$")
CONTRACT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a typed MCP service from templates/service-template."
    )
    parser.add_argument("--name", required=True, help="Service slug, e.g. proxmox")
    parser.add_argument(
        "--contract",
        default="",
        help="Contract family, e.g. flowoox.proxmox. Defaults to flowoox.<name>.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output directory. Defaults to services/<name>-mcp.",
    )
    return parser.parse_args()


def validate(name: str, contract: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise SystemExit(
            "--name must be lowercase kebab-case, 3-50 chars, starting with a letter"
        )
    if not CONTRACT_RE.fullmatch(contract):
        raise SystemExit("--contract must be a dotted/dashed lowercase identifier")


def rewrite_text(path: Path, replacements: dict[str, str]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return
    for old, new in replacements.items():
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    args = parse_args()
    name = args.name.strip()
    contract = args.contract.strip() or f"flowoox.{name.replace('-', '.')}"
    validate(name, contract)

    repo_root = Path(__file__).resolve().parents[1]
    template = repo_root / "templates" / "service-template"
    target = Path(args.output).resolve() if args.output else repo_root / "services" / f"{name}-mcp"

    if not template.is_dir():
        raise SystemExit(f"template not found: {template}")
    if target.exists():
        raise SystemExit(f"target already exists: {target}")

    package = f"{name.replace('-', '_')}_mcp"
    project = f"flowoox-mcp-{name}"
    console = f"mcp-{name}"
    display = " ".join(part.capitalize() for part in name.split("-"))

    shutil.copytree(template, target)

    old_package_dir = target / "src" / "example_mcp"
    if old_package_dir.exists():
        old_package_dir.rename(target / "src" / package)

    replacements = {
        "example_mcp": package,
        "flowoox-mcp-example": project,
        "mcp-example": console,
        "flowoox.example": contract,
        "Flowoox MCP Example": f"Flowoox MCP {display}",
        "MCP service template": f"{display} MCP",
    }

    for path in target.rglob("*"):
        if path.is_file():
            rewrite_text(path, replacements)

    print(f"Created {target}")
    print(f"Package:  {package}")
    print(f"Project:  {project}")
    print(f"Contract: {contract}")
    print("Next: replace the read-only echo capability with explicit typed handlers and tests.")


if __name__ == "__main__":
    main()
