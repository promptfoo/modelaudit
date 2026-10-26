"""Regression tests for security-sensitive dependency lock entries."""

import json
import re
from pathlib import Path

import pytest
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

ROOT_DIR = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT_DIR / "uv.lock"
ROOT_PYPROJECT = ROOT_DIR / "pyproject.toml"
RENOVATE_CONFIG = ROOT_DIR / "renovate.json"
PICKLESCAN_PYPROJECT = ROOT_DIR / "packages" / "modelaudit-picklescan" / "pyproject.toml"
PATCHED_GITPYTHON_FLOOR = (3, 2, 0)
PATCHED_ANYIO_FLOOR = (4, 14, 2)
PATCHED_GITPYTHON_REQUIREMENT = "gitpython>=3.2.0"
PATCHED_ANYIO_REQUIREMENT = "anyio>=4.14.2"
PINNED_MATURIN_BACKEND = "maturin===1.13.3"
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
        ("anyio", PATCHED_ANYIO_FLOOR),
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
        assert PATCHED_GITPYTHON_REQUIREMENT in optional_dependencies[extra]


def test_base_install_requires_patched_anyio() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))

    assert PATCHED_ANYIO_REQUIREMENT in root_config["project"]["dependencies"]


@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_filelock_requirements_exclude_vulnerable_releases(python_version: str) -> None:
    project = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))["project"]
    environment = {"python_version": python_version, "python_full_version": f"{python_version}.0"}
    requirements = [
        requirement
        for entry in project["dependencies"]
        if (requirement := Requirement(entry)).name == "filelock"
        and (requirement.marker is None or requirement.marker.evaluate(environment))
    ]

    assert len(requirements) == 1
    specifier = requirements[0].specifier
    for vulnerable_version in ("3.20.0", "3.20.1", "3.20.2", "3.20.4", "3.22.0", "4.1.0", "4.2.0", "4.2.1rc1"):
        assert not specifier.contains(vulnerable_version, prereleases=True)
    if python_version == "3.10":
        assert specifier == SpecifierSet("==3.20.3")
    else:
        assert not specifier.contains("3.20.3")
        for patched_version in ("4.2.1", "4.2.4", "4.3.0"):
            assert specifier.contains(patched_version)


@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_filelock_lock_preserves_secure_python_cohorts(python_version: str) -> None:
    lock = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    environment = {"python_version": python_version, "python_full_version": f"{python_version}.0"}
    packages = [
        package
        for package in lock["package"]
        if package["name"] == "filelock"
        and (
            "resolution-markers" not in package
            or any(Marker(marker).evaluate(environment) for marker in package["resolution-markers"])
        )
    ]

    assert len(packages) == 1
    locked_version = Version(packages[0]["version"])
    if python_version == "3.10":
        assert locked_version == Version("3.20.3")
    else:
        assert locked_version >= Version("4.2.1")
    project = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert any(
        requirement.specifier.contains(locked_version)
        for entry in project["dependencies"]
        if (requirement := Requirement(entry)).name == "filelock"
        and (requirement.marker is None or requirement.marker.evaluate(environment))
    )


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


def test_picklescan_msrv_supports_locked_pyo3() -> None:
    package_dir = PICKLESCAN_PYPROJECT.parent
    cargo_config = tomllib.loads((package_dir / "Cargo.toml").read_text(encoding="utf-8"))
    cargo_lock = tomllib.loads((package_dir / "Cargo.lock").read_text(encoding="utf-8"))
    pyo3 = next(package for package in cargo_lock["package"] if package["name"] == "pyo3")

    # PyO3 0.30 uses Rust 2024: https://github.com/PyO3/pyo3/blob/v0.30.1/Cargo.toml
    if Version(pyo3["version"]) >= Version("0.30.0"):
        assert Version(cargo_config["package"]["rust-version"]) >= Version("1.85")


def test_root_requires_hardened_picklescan_release() -> None:
    root_config = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))
    dependency = next(
        requirement
        for entry in root_config["project"]["dependencies"]
        if (requirement := Requirement(entry)).name == "modelaudit-picklescan"
    )

    assert dependency.marker is None
    # Root upgrades must receive these fixes, while later floor increases remain valid.
    bounds = {specifier.operator: specifier.version for specifier in dependency.specifier}
    assert len(dependency.specifier) == 2
    assert set(bounds) == {">=", "<"}
    assert Version(bounds[">="]) >= Version("0.1.13")
    assert Version(bounds["<"]) == Version("0.2.0")
    locked_version = ".".join(str(part) for part in _locked_version(_lock_package_block("modelaudit-picklescan")))
    assert dependency.specifier.contains(locked_version)


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


def test_renovate_keeps_legacy_xgboost_cohort_compatible() -> None:
    renovate_config = json.loads(RENOVATE_CONFIG.read_text(encoding="utf-8"))
    compatibility_rules = [
        rule for rule in renovate_config["packageRules"] if "xgboost" in rule.get("matchPackageNames", [])
    ]

    assert len(compatibility_rules) == 1
    rule = compatibility_rules[0]
    assert rule["matchManagers"] == ["pep621"]
    assert rule["matchFileNames"] == ["pyproject.toml"]
    assert rule["matchPackageNames"] == ["xgboost"]
    assert rule["matchCurrentValue"] == r"/<3\.3/"
    assert rule["allowedVersions"] == "<3.3"

    current_value_pattern = re.compile(rule["matchCurrentValue"].removeprefix("/").removesuffix("/"))
    assert current_value_pattern.search(">=3.2,<3.3") is not None
    assert current_value_pattern.search(">=3.4,<3.5") is None


@pytest.mark.parametrize("extra", ["h5", "numpy1", "all-ci", "all"])
@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_h5py_requirements_preserve_older_python_floors(extra: str, python_version: str) -> None:
    project = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))["project"]
    requirements = [
        requirement
        for entry in project["optional-dependencies"][extra]
        if (requirement := Requirement(entry)).name == "h5py"
        and (requirement.marker is None or requirement.marker.evaluate({"python_version": python_version}))
    ]

    assert len(requirements) == 1
    requirement = requirements[0]
    assert requirement.specifier.contains("3.15.0")
    assert not requirement.specifier.contains("4.0.0")
    assert requirement.specifier.contains("3.14.0") is (python_version != "3.14")


def test_renovate_python_updates_follow_runtime_support() -> None:
    project = tomllib.loads(ROOT_PYPROJECT.read_text(encoding="utf-8"))["project"]
    supported_versions = sorted(
        Version(match.group(1))
        for classifier in project["classifiers"]
        if (match := re.fullmatch(r"Programming Language :: Python :: (3\.\d+)", classifier))
    )
    assert supported_versions
    last_supported = supported_versions[-1]
    next_minor = Version(f"{last_supported.major}.{last_supported.minor + 1}")
    versions = [*supported_versions, next_minor]
    runtime_support = SpecifierSet(project["requires-python"])
    rules = json.loads(RENOVATE_CONFIG.read_text(encoding="utf-8"))["packageRules"]
    python_rules = [(index, rule) for index, rule in enumerate(rules) if rule.get("matchPackageNames") == ["python"]]
    global_rules = [(index, rule) for index, rule in python_rules if "matchFileNames" not in rule]
    assert len(global_rules) == 1
    global_index, global_rule = global_rules[0]
    update_policy = SpecifierSet(global_rule["allowedVersions"])

    for version in versions:
        assert update_policy.contains(version) == runtime_support.contains(version)

    tensorflow_rules = [
        (index, rule) for index, rule in python_rules if rule.get("matchFileNames") == ["Dockerfile.tensorflow"]
    ]
    assert len(tensorflow_rules) == 1
    tensorflow_index, tensorflow_rule = tensorflow_rules[0]
    assert tensorflow_index > global_index
    tensorflow_policy = SpecifierSet(tensorflow_rule["allowedVersions"])
    tensorflow_requirements = [
        requirement
        for entry in project["optional-dependencies"]["tensorflow"]
        if (requirement := Requirement(entry)).name == "tensorflow"
    ]
    assert len(tensorflow_requirements) == 1
    image = (ROOT_DIR / "Dockerfile.tensorflow").read_text(encoding="utf-8")
    image_match = re.search(r"(?m)^ARG PYTHON_IMAGE=python:(\d+\.\d+)", image)
    assert image_match is not None
    image_version = Version(image_match.group(1))
    for version in versions:
        if version < image_version:
            continue
        expected = any(
            requirement.marker is None or requirement.marker.evaluate({"python_version": str(version)})
            for requirement in tensorflow_requirements
        )
        assert tensorflow_policy.contains(version) == expected
