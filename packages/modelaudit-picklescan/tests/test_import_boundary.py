from __future__ import annotations

from pathlib import Path

PACKAGE_SRC = Path(__file__).resolve().parents[1] / "src" / "modelaudit_picklescan"


def test_standalone_package_does_not_import_modelaudit() -> None:
    forbidden_imports: list[str] = []

    for path in PACKAGE_SRC.rglob("*.py"):
        source = path.read_text()
        if "from modelaudit" in source or "import modelaudit" in source:
            forbidden_imports.append(str(path.relative_to(PACKAGE_SRC.parents[1])))

    assert forbidden_imports == []
