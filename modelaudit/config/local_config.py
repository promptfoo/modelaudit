"""Helpers for resolving local ModelAudit configuration files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore


@dataclass(frozen=True)
class LocalConfigCandidate:
    """Resolved local config file discovered from scan targets."""

    config_dir: Path
    config_path: Path
    source: str


def find_local_config_for_paths(paths: list[str]) -> LocalConfigCandidate | None:
    """Return a shared local config candidate when all local paths resolve to one."""
    if not paths:
        return None

    resolved_candidates: list[LocalConfigCandidate] = []
    for path_str in paths:
        path = Path(path_str)
        if not path.exists():
            return None

        resolved_path = path.resolve()
        start_dir = resolved_path if resolved_path.is_dir() else resolved_path.parent
        candidate = _find_local_config(start_dir)
        if candidate is None:
            return None
        resolved_candidates.append(candidate)

    first_candidate = resolved_candidates[0]
    if all(candidate == first_candidate for candidate in resolved_candidates[1:]):
        return first_candidate
    return None


def _find_local_config(start_dir: Path) -> LocalConfigCandidate | None:
    """Walk parent directories and return the nearest supported config file."""
    current = start_dir
    while True:
        modelaudit_toml = current / ".modelaudit.toml"
        if modelaudit_toml.exists() and modelaudit_toml.is_file():
            return LocalConfigCandidate(config_dir=current, config_path=modelaudit_toml, source="modelaudit_toml")

        pyproject_toml = current / "pyproject.toml"
        if pyproject_toml.exists() and pyproject_toml.is_file() and _has_modelaudit_section(pyproject_toml):
            return LocalConfigCandidate(config_dir=current, config_path=pyproject_toml, source="pyproject_toml")

        if current == current.parent:
            return None
        current = current.parent


def _has_modelaudit_section(pyproject_path: Path) -> bool:
    """Return True when pyproject.toml contains a [tool.modelaudit] section."""
    try:
        with pyproject_path.open("rb") as handle:
            data = tomllib.load(handle)
        return bool(data.get("tool", {}).get("modelaudit"))
    except Exception:
        return False
