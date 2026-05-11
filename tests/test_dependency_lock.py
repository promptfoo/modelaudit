"""Regression tests for security-sensitive dependency lock entries."""

import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT_DIR / "uv.lock"
PATCHED_GITPYTHON_FLOOR = (3, 1, 50)


def _lock_package_block(name: str) -> str:
    for block in LOCKFILE.read_text().split("\n[[package]]\n"):
        if re.search(rf'(?m)^name = "{re.escape(name)}"$', block):
            return block

    raise AssertionError(f"Package {name!r} is not present in uv.lock")


def _locked_version(block: str) -> tuple[int, ...]:
    match = re.search(r'(?m)^version = "([0-9]+(?:\.[0-9]+)*)"$', block)
    if match is None:
        raise AssertionError("Package block is missing a numeric version field")

    return tuple(int(part) for part in match.group(1).split("."))


def _dependency_names(block: str) -> set[str]:
    dependencies: set[str] = set()
    in_dependencies = False
    for line in block.splitlines():
        if line == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies and line == "]":
            break
        if in_dependencies:
            match = re.search(r'\{ name = "([^"]+)"', line)
            if match:
                dependencies.add(match.group(1))

    return dependencies


def test_gitpython_lock_stays_on_patched_release_floor() -> None:
    gitpython_block = _lock_package_block("gitpython")

    assert _locked_version(gitpython_block) >= PATCHED_GITPYTHON_FLOOR
    assert "gitpython-3.1.49" not in gitpython_block


def test_mlflow_skinny_transitive_gitpython_dependency_is_guarded() -> None:
    mlflow_skinny_block = _lock_package_block("mlflow-skinny")

    assert "gitpython" in _dependency_names(mlflow_skinny_block)
