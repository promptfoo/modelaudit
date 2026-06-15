"""Internal helpers for non-symlink path hardening."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import Path


def _tighten_permissions(path: Path, mode: int) -> None:
    """Best-effort permission hardening for sensitive local paths."""
    if os.name == "nt":
        return

    with suppress(OSError):
        path.chmod(mode)


def _has_symlink_component(path: Path) -> bool:
    """Return True when path or any ancestor is a symlink or unreadable."""
    current = path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        if current == current.parent:
            return False
        current = current.parent


def _is_secure_directory(path: Path) -> bool:
    """Return True when the path is a usable non-symlink directory."""
    try:
        return path.exists() and path.is_dir() and not _has_symlink_component(path)
    except OSError:
        return False


def _ensure_secure_directory(path: Path) -> bool:
    """Create a directory when possible and reject symlinked targets."""
    if _has_symlink_component(path):
        return False

    missing_directories: list[Path] = []
    current = path
    while not current.exists():
        missing_directories.append(current)
        if current == current.parent:
            break
        current = current.parent

    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError:
        return False

    if not _is_secure_directory(path):
        return False

    for created_dir in missing_directories:
        _tighten_permissions(created_dir, 0o700)
    _tighten_permissions(path, 0o700)
    return True


def _is_private_descriptor_bound_regular_file(path: str | Path) -> bool:
    """Recognize one regular-file symlink below this process's private directory descriptor."""
    parts = Path(path).parts
    descriptor_index: int | None = None
    if len(parts) == 6 and parts[1] == "proc" and parts[3] == "fd":
        if parts[2] not in {"self", str(os.getpid())}:
            return False
        descriptor_index = 4
    elif len(parts) == 5 and parts[1:3] == ("dev", "fd"):
        descriptor_index = 3
    if descriptor_index is None or parts[-1] in {"", ".", ".."}:
        return False
    try:
        descriptor = int(parts[descriptor_index])
        root_stat = os.fstat(descriptor)
        entry_stat = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        target_stat = os.stat(parts[-1], dir_fd=descriptor)
    except (OSError, ValueError):
        return False
    effective_uid = getattr(os, "geteuid", lambda: root_stat.st_uid)()
    return bool(
        stat.S_ISDIR(root_stat.st_mode)
        and root_stat.st_uid == effective_uid
        and not stat.S_IMODE(root_stat.st_mode) & 0o077
        and stat.S_ISLNK(entry_stat.st_mode)
        and stat.S_ISREG(target_stat.st_mode)
    )
