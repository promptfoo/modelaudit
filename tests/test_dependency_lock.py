"""Regression tests for security-sensitive dependency lock entries."""

import re
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

ROOT_DIR = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT_DIR / "uv.lock"
ROOT_PYPROJECT = ROOT_DIR / "pyproject.toml"
PICKLESCAN_PYPROJECT = ROOT_DIR / "packages" / "modelaudit-picklescan" / "pyproject.toml"
PATCHED_GITPYTHON_FLOOR = (3, 1, 58)
PINNED_MATURIN_BACKEND = "maturin===1.13.3"
REQUIRED_PICKLESCAN_RELEASE = "modelaudit-picklescan>=0.1.10,<0.2.0"
PATCHED_PY7ZR_REQUIREMENT = "py7zr>=1.1.3"
PY7ZR_EXTRAS = ("sevenzip", "all-ci", "all")
PATCHED_MLFLOW_CLIENT_REQUIREMENT = "mlflow-skinny>=3.13.0"
MLFLOW_EXTRAS = ("mlflow", "all-ci", "all")
MLFLOW_SQL_STORAGE_REQUIREMENTS = ("sqlalchemy>=2.0.49", "alembic>=1.18.4")
PATCHED_SQLPARSE_REQUIREMENT = "sqlparse>=0.6.0"
NUMPY_REQUIREMENTS = {
    "numpy>=1.19.0,<2.0; python_version == '3.10'",
    "numpy>=2.4.3,<2.5; python_version == '3.11'",
    "numpy>=2.5,<2.6; python_version >= '3.12'",
}
XGBOOST_REQUIREMENTS = {
    "xgboost>=3.2,<3.3; python_version < '3.12'",
    "xgboost>=3.4,<3.5; python_version >= '3.12'",
}
XGBOOST_EXTRAS = ("xgboost", "all-ci", "all")


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


@pytest.mark.parametrize(
    ("package_name", "patched_floor"),
    [
        ("aiohttp", (3, 14, 3)),
        ("cryptography", (50, 0, 0)),
        ("keras", (3, 15, 0)),
        ("sqlparse", (0, 6, 0)),
    ],
)
def test_security_sensitive_dependencies_stay_on_patched_release_floors(
    package_name: str,
    patched_floor: tuple[int, ...],
) -> None:
    assert _locked_version(_lock_package_block(package_name)) >= patched_floor


def test_mlflow_skinny_transitive_gitpython_dependency_is_guarded() -> None:
    mlflow_skinny_block = _lock_package_block("mlflow-skinny")

    assert _locked_version(mlflow_skinny_block) >= (3, 13, 0)
    assert "gitpython" in _dependency_names(mlflow_skinny_block)


def test_mlflow_extras_use_the_hardened_tracking_client() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    optional_dependencies = root_config["project"]["optional-dependencies"]

    for extra in MLFLOW_EXTRAS:
        assert PATCHED_MLFLOW_CLIENT_REQUIREMENT in optional_dependencies[extra]


@pytest.mark.parametrize("extra", MLFLOW_EXTRAS)
def test_mlflow_extras_preserve_sql_backed_model_registries(extra: str) -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    optional_dependencies = root_config["project"]["optional-dependencies"][extra]

    for requirement in MLFLOW_SQL_STORAGE_REQUIREMENTS:
        assert requirement in optional_dependencies
        assert _lock_package_block(requirement.split(">=", maxsplit=1)[0])


@pytest.mark.parametrize("extra", MLFLOW_EXTRAS)
def test_mlflow_extras_require_patched_sqlparse(extra: str) -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    optional_dependencies = root_config["project"]["optional-dependencies"][extra]

    assert PATCHED_SQLPARSE_REQUIREMENT in optional_dependencies


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


@pytest.mark.parametrize("extra", XGBOOST_EXTRAS)
def test_xgboost_requirements_follow_supported_python_versions(extra: str) -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    optional_dependencies = root_config["project"]["optional-dependencies"][extra]

    requirements = {requirement for requirement in optional_dependencies if requirement.startswith("xgboost")}

    assert requirements == XGBOOST_REQUIREMENTS
