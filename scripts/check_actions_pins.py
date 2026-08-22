from __future__ import annotations

import re
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
USES_PATTERN = re.compile(r"\buses:\s*['\"]?([^'\"#\s]+)")
FULL_SHA_PATTERN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def iter_external_uses() -> list[tuple[Path, int, str]]:
    found: list[tuple[Path, int, str]] = []
    for path in sorted((*WORKFLOW_DIR.glob("*.yml"), *WORKFLOW_DIR.glob("*.yaml"))):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_PATTERN.search(line)
            if not match:
                continue
            target = match.group(1)
            if target.startswith("./") or target.startswith("docker://"):
                continue
            found.append((path, line_number, target))
    return found


def main() -> int:
    violations = [
        (path, line_number, target)
        for path, line_number, target in iter_external_uses()
        if not FULL_SHA_PATTERN.fullmatch(target)
    ]
    if not violations:
        print("All external GitHub Actions references are pinned to full commit SHAs.")
        return 0

    print("Mutable or non-SHA GitHub Actions references found:")
    for path, line_number, target in violations:
        print(f"  {path}:{line_number}: {target}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
