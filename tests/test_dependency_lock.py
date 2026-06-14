"""Regression tests for security-sensitive dependency lock entries."""

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

ROOT_DIR = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT_DIR / "uv.lock"
ROOT_PYPROJECT = ROOT_DIR / "pyproject.toml"
PICKLESCAN_PYPROJECT = ROOT_DIR / "packages" / "modelaudit-picklescan" / "pyproject.toml"
PATCHED_GITPYTHON_FLOOR = (3, 1, 50)
PINNED_MATURIN_BACKEND = "maturin===1.13.3"
REQUIRED_PICKLESCAN_RELEASE = "modelaudit-picklescan>=0.1.7,<0.2.0"


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


def test_picklescan_build_backend_is_exactly_pinned() -> None:
    package_config = tomllib.loads(PICKLESCAN_PYPROJECT.read_text(encoding="utf-8"))
    build_system = package_config["build-system"]

    assert build_system["build-backend"] == "maturin"
    # PEP 440 `==1.13.3` also accepts local versions such as `1.13.3+local`.
    assert build_system["requires"] == [PINNED_MATURIN_BACKEND]


def test_root_requires_hardened_picklescan_release() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))

    assert REQUIRED_PICKLESCAN_RELEASE in root_config["project"]["dependencies"]
