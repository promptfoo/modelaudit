"""Regression tests for security-sensitive dependency lock entries."""

import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

ROOT_DIR = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT_DIR / "uv.lock"
ROOT_PYPROJECT = ROOT_DIR / "pyproject.toml"
RENOVATE_CONFIG = ROOT_DIR / "renovate.json"
PICKLESCAN_PYPROJECT = ROOT_DIR / "packages" / "modelaudit-picklescan" / "pyproject.toml"
PATCHED_GITPYTHON_FLOOR = (3, 1, 50)
PINNED_MATURIN_BACKEND = "maturin===1.13.3"
REQUIRED_PICKLESCAN_RELEASE = "modelaudit-picklescan>=0.1.10,<0.2.0"
PATCHED_PY7ZR_REQUIREMENT = "py7zr>=1.1.3"
PY7ZR_EXTRAS = ("sevenzip", "all-ci", "all")
NUMPY_REQUIREMENTS = {
    "numpy>=1.19.0,<2.0; python_version == '3.10'",
    "numpy>=2.4.3,<2.5; python_version == '3.11'",
    "numpy>=2.5,<2.6; python_version >= '3.12'",
}


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


def test_py7zr_extras_require_patched_release() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    optional_dependencies = root_config["project"]["optional-dependencies"]

    for extra in PY7ZR_EXTRAS:
        assert PATCHED_PY7ZR_REQUIREMENT in optional_dependencies[extra]


def test_numpy_requirements_follow_supported_python_versions() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    project = root_config["project"]

    root_requirements = {requirement for requirement in project["dependencies"] if requirement.startswith("numpy")}
    extra_requirements = {
        requirement for requirement in project["optional-dependencies"]["numpy1"] if requirement.startswith("numpy")
    }

    assert root_requirements == NUMPY_REQUIREMENTS
    assert extra_requirements == NUMPY_REQUIREMENTS


def test_renovate_keeps_xgboost_compatible_with_supported_python_versions() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    project = root_config["project"]
    optional_dependencies = project["optional-dependencies"]
    renovate_config = json.loads(RENOVATE_CONFIG.read_text(encoding="utf-8"))

    assert project["requires-python"] == ">=3.10,<3.14"
    for extra in ("xgboost", "all-ci", "all"):
        xgboost_requirements = [
            requirement for requirement in optional_dependencies[extra] if requirement.startswith("xgboost")
        ]
        assert xgboost_requirements == ["xgboost>=3.2,<3.3"]

    compatibility_rules = [
        rule for rule in renovate_config["packageRules"] if "xgboost" in rule.get("matchPackageNames", [])
    ]

    assert len(compatibility_rules) == 1
    assert compatibility_rules[0]["matchManagers"] == ["pep621"]
    assert compatibility_rules[0]["matchFileNames"] == ["pyproject.toml"]
    assert compatibility_rules[0]["allowedVersions"] == "<3.3"
