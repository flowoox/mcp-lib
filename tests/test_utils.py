from pathlib import Path

import pytest

from mcp_lib.utils import resolve_contained_path, safe_relative_destination


def test_safe_destination_removes_traversal_characters() -> None:
    destination = safe_relative_destination("Artist", "../Album")
    assert ".." not in Path(destination).parts


def test_contained_path_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "downloads"
    root.mkdir()
    with pytest.raises(ValueError):
        resolve_contained_path(root, root / ".." / "secret")
