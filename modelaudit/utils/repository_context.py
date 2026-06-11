"""Trusted repository-level file inventory helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Final

REPOSITORY_FILE_INVENTORY_CONFIG_KEY: Final[str] = "_modelaudit_repository_file_inventory"
REPOSITORY_SCAN_ROOT_CONFIG_KEY: Final[str] = "_modelaudit_repository_scan_root"
REPOSITORY_CURRENT_FILE_CONFIG_KEY: Final[str] = "_modelaudit_repository_current_file"


def normalize_repository_member_path(value: object) -> str | None:
    """Normalize a repository member path, rejecting absolute or escaping names."""
    if not isinstance(value, str):
        return None

    candidate = value.strip().replace("\\", "/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    if not candidate or candidate.endswith("/"):
        return None

    path = PurePosixPath(candidate)
    if path.is_absolute():
        return None
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        return None

    return path.as_posix()


def repository_file_inventory_from_config(config: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return normalized repository member paths from scanner config."""
    if not config:
        return ()

    raw_inventory = config.get(REPOSITORY_FILE_INVENTORY_CONFIG_KEY)
    if isinstance(raw_inventory, Mapping):
        raw_inventory = raw_inventory.get("files")

    if isinstance(raw_inventory, str):
        candidates: Iterable[object] = (raw_inventory,)
    elif isinstance(raw_inventory, Iterable) and not isinstance(raw_inventory, (bytes, bytearray)):
        candidates = raw_inventory
    else:
        return ()

    inventory: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = normalize_repository_member_path(candidate)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        inventory.append(normalized)

    return tuple(inventory)


def _current_repository_member_path(model_path: str, config: Mapping[str, Any]) -> str | None:
    configured_current = normalize_repository_member_path(config.get(REPOSITORY_CURRENT_FILE_CONFIG_KEY))
    if configured_current is not None:
        return configured_current

    scan_root = config.get(REPOSITORY_SCAN_ROOT_CONFIG_KEY)
    if isinstance(scan_root, str) and scan_root.strip():
        try:
            relative_path = Path(model_path).resolve().relative_to(Path(scan_root).resolve()).as_posix()
        except (OSError, RuntimeError, ValueError):
            pass
        else:
            normalized_relative = normalize_repository_member_path(relative_path)
            if normalized_relative is not None:
                return normalized_relative

    return normalize_repository_member_path(Path(model_path).name)


def repository_has_safetensors_sibling(model_path: str, config: Mapping[str, Any] | None) -> bool:
    """Return whether repository inventory lists a same-directory SafeTensors alternative."""
    if not config:
        return False

    inventory = repository_file_inventory_from_config(config)
    if not inventory:
        return False

    current_member = _current_repository_member_path(model_path, config)
    if current_member is None:
        return False

    current_parent = PurePosixPath(current_member).parent.as_posix()
    if current_parent == ".":
        current_parent = ""

    for member in inventory:
        if member == current_member:
            continue
        member_path = PurePosixPath(member)
        if member_path.suffix.lower() != ".safetensors":
            continue
        member_parent = member_path.parent.as_posix()
        if member_parent == ".":
            member_parent = ""
        if member_parent == current_parent:
            return True

    return False
