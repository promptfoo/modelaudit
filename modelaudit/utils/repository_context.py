"""Trusted repository-level file inventory helpers."""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

REPOSITORY_FILE_INVENTORY_CONFIG_KEY: Final[str] = "_modelaudit_repository_file_inventory"
REPOSITORY_SCAN_ROOT_CONFIG_KEY: Final[str] = "_modelaudit_repository_scan_root"
REPOSITORY_CURRENT_FILE_CONFIG_KEY: Final[str] = "_modelaudit_repository_current_file"
MAX_REPOSITORY_INVENTORY_FILES: Final[int] = 100_000
MAX_SAFETENSORS_HEADER_BYTES: Final[int] = 10 * 1024 * 1024


@dataclass(frozen=True)
class RepositoryFileInventory:
    """Normalized repository inventory indexed for SafeTensors sibling checks."""

    files: tuple[str, ...]
    safetensors_by_parent: Mapping[str, frozenset[str]]


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


def _raw_inventory_files(raw_inventory: object) -> Iterable[object] | None:
    if isinstance(raw_inventory, RepositoryFileInventory):
        return raw_inventory.files
    if isinstance(raw_inventory, Mapping):
        raw_inventory = raw_inventory.get("files")

    if isinstance(raw_inventory, str):
        return (raw_inventory,)
    if isinstance(raw_inventory, Iterable) and not isinstance(raw_inventory, (bytes, bytearray)):
        return raw_inventory
    return None


def repository_file_inventory_from_config(config: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return normalized repository member paths from scanner config."""
    return repository_file_inventory_context_from_config(config).files


def repository_file_inventory_context_from_config(config: Mapping[str, Any] | None) -> RepositoryFileInventory:
    """Return a bounded, normalized, indexed repository inventory from scanner config."""
    if not config:
        return RepositoryFileInventory((), {})

    raw_inventory = config.get(REPOSITORY_FILE_INVENTORY_CONFIG_KEY)
    if isinstance(raw_inventory, RepositoryFileInventory):
        return raw_inventory

    candidates = _raw_inventory_files(raw_inventory)
    if candidates is None:
        return RepositoryFileInventory((), {})

    inventory: list[str] = []
    seen: set[str] = set()
    safetensors_by_parent: dict[str, set[str]] = {}
    for index, candidate in enumerate(candidates):
        if index >= MAX_REPOSITORY_INVENTORY_FILES:
            break
        normalized = normalize_repository_member_path(candidate)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        inventory.append(normalized)
        member_path = PurePosixPath(normalized)
        if member_path.suffix.lower() == ".safetensors":
            parent = _repository_parent(member_path)
            safetensors_by_parent.setdefault(parent, set()).add(member_path.name)

    return RepositoryFileInventory(
        tuple(inventory),
        {parent: frozenset(names) for parent, names in safetensors_by_parent.items()},
    )


def _repository_parent(path: PurePosixPath) -> str:
    parent = path.parent.as_posix()
    return "" if parent == "." else parent


def _is_plausible_local_safetensors_file(path: Path) -> bool:
    try:
        file_size = path.stat().st_size
    except OSError:
        return False
    if file_size <= 8:
        return False
    try:
        with path.open("rb") as handle:
            header_prefix = handle.read(8)
            if len(header_prefix) != 8:
                return False
            (header_size,) = struct.unpack("<Q", header_prefix)
            if header_size <= 0 or header_size > MAX_SAFETENSORS_HEADER_BYTES:
                return False
            if 8 + header_size > file_size:
                return False
            header = handle.read(header_size)
    except Exception:
        return False
    try:
        return isinstance(json.loads(header.decode("utf-8")), dict)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _local_repository_member_path(config: Mapping[str, Any], member_path: str) -> Path | None:
    scan_root = config.get(REPOSITORY_SCAN_ROOT_CONFIG_KEY)
    if not isinstance(scan_root, str) or not scan_root.strip():
        return None
    normalized_member = normalize_repository_member_path(member_path)
    if normalized_member is None:
        return None
    try:
        root = Path(scan_root).resolve()
        candidate = (root / normalized_member).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate


def _repository_inventory_safetensors_candidate_is_plausible(
    config: Mapping[str, Any],
    member_path: str,
) -> bool:
    local_path = _local_repository_member_path(config, member_path)
    if local_path is None:
        return True
    if not local_path.exists():
        return True
    return local_path.is_file() and _is_plausible_local_safetensors_file(local_path)


def safetensors_alternative_filenames_for_member(member_name: str) -> frozenset[str]:
    """Return exact SafeTensors filenames that plausibly replace a PyTorch member."""
    name = PurePosixPath(member_name.replace("\\", "/")).name
    path = PurePosixPath(name)
    candidates: set[str] = set()
    if path.suffix:
        candidates.add(f"{path.stem}.safetensors")
    if name == "pytorch_model.bin":
        candidates.add("model.safetensors")

    shard_match = re.fullmatch(r"pytorch_model-(\d{5}-of-\d{5})\.bin", name)
    if shard_match:
        candidates.add(f"model-{shard_match.group(1)}.safetensors")

    return frozenset(candidates)


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


def repository_has_safetensors_sibling(
    model_path: str,
    config: Mapping[str, Any] | None,
    inventory_context: RepositoryFileInventory | None = None,
) -> bool:
    """Return whether repository inventory lists a same-directory SafeTensors alternative."""
    if not config:
        return False

    context = inventory_context or repository_file_inventory_context_from_config(config)
    if not context.files:
        return False

    current_member = _current_repository_member_path(model_path, config)
    if current_member is None:
        return False

    current_path = PurePosixPath(current_member)
    current_parent = _repository_parent(current_path)
    allowed_names = safetensors_alternative_filenames_for_member(current_path.name)
    if not allowed_names:
        return False

    candidate_names = context.safetensors_by_parent.get(current_parent, frozenset()) & allowed_names
    for candidate_name in candidate_names:
        candidate_member = f"{current_parent}/{candidate_name}" if current_parent else candidate_name
        if _repository_inventory_safetensors_candidate_is_plausible(config, candidate_member):
            return True
    return False
