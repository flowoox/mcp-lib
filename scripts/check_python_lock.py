from __future__ import annotations

import argparse
import re
from collections import deque
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
LOCAL_PREFIX = "flowoox-mcp-"


def load_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.fullmatch(line)
        if not match:
            raise SystemExit(f"{path}:{number}: dependency is not exactly pinned: {line}")
        name = canonicalize_name(match.group(1))
        if name in pins:
            raise SystemExit(f"{path}:{number}: duplicate dependency pin: {name}")
        pins[name] = match.group(2)
    if not pins:
        raise SystemExit(f"{path}: no dependency pins found")
    return pins


def validate_installed_graph(pins: dict[str, str], roots: list[str]) -> None:
    queue = deque(canonicalize_name(root) for root in roots)
    visited: set[str] = set()
    problems: list[str] = []

    while queue:
        name = queue.popleft()
        if name in visited:
            continue
        visited.add(name)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            problems.append(f"required distribution is not installed: {name}")
            continue

        local = name.startswith(LOCAL_PREFIX)
        if not local:
            expected = pins.get(name)
            if expected is None:
                problems.append(f"installed dependency is missing from lock: {name}=={dist.version}")
            elif dist.version != expected:
                problems.append(
                    f"installed dependency differs from lock: {name}=={dist.version} (expected {expected})"
                )

        for raw_requirement in dist.requires or []:
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None and not requirement.marker.evaluate():
                continue
            queue.append(canonicalize_name(requirement.name))

    if problems:
        raise SystemExit("Python dependency lock validation failed:\n  " + "\n  ".join(sorted(problems)))

    print(
        f"Dependency lock covers the installed transitive graph for {', '.join(roots)} "
        f"({len(visited)} distributions traversed)."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path("constraints/python312.lock"))
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()

    pins = load_pins(args.lock)
    validate_installed_graph(pins, args.roots)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
