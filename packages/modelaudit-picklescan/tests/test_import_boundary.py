from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src" / "modelaudit_picklescan"


def test_standalone_package_does_not_import_modelaudit() -> None:
    forbidden_imports: list[str] = []

    for path in PACKAGE_SRC.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                alias.name == "modelaudit" or alias.name.startswith("modelaudit.") for alias in node.names
            ):
                forbidden_imports.append(str(path.relative_to(PACKAGE_SRC.parents[1])))
                break
            if (
                isinstance(node, ast.ImportFrom)
                and node.module is not None
                and (node.module == "modelaudit" or node.module.startswith("modelaudit."))
            ):
                forbidden_imports.append(str(path.relative_to(PACKAGE_SRC.parents[1])))
                break

    assert forbidden_imports == []


def test_standalone_package_declares_typed_marker() -> None:
    assert (PACKAGE_SRC / "py.typed").is_file()
