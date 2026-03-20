"""Secure persistence for trusted local ModelAudit configuration files."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from ..config.local_config import LocalConfigCandidate

TRUST_STORE_VERSION = 1


@dataclass(frozen=True)
class TrustedConfigRecord:
    """Persisted trust metadata for a local config directory."""

    config_path: str
    config_sha256: str


class TrustedConfigStore:
    """Read and write trusted local config state under the cache directory."""

    def __init__(self, store_path: Path | None = None) -> None:
        self.store_path = store_path or (Path.home() / ".modelaudit" / "cache" / "trusted_local_configs.json")

    def is_trusted(self, candidate: LocalConfigCandidate) -> bool:
        """Return True when a candidate matches a previously trusted config hash."""
        records = self._load_records()
        key = str(candidate.config_dir)
        record = records.get(key)
        if record is None:
            return False

        if record.config_path != str(candidate.config_path):
            return False

        current_hash = self._hash_config(candidate.config_path)
        return current_hash is not None and current_hash == record.config_sha256

    def trust(self, candidate: LocalConfigCandidate) -> None:
        """Persist trust for a resolved local config candidate."""
        config_hash = self._hash_config(candidate.config_path)
        if config_hash is None:
            return

        records = self._load_records()
        records[str(candidate.config_dir)] = TrustedConfigRecord(
            config_path=str(candidate.config_path),
            config_sha256=config_hash,
        )
        self._write_records(records)

    def _load_records(self) -> dict[str, TrustedConfigRecord]:
        """Load trusted config records from disk."""
        if not self._is_secure_target(self.store_path):
            return {}

        try:
            if not self.store_path.exists():
                return {}
            if self.store_path.is_symlink() or not self.store_path.is_file():
                return {}

            with self.store_path.open(encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            return {}

        if not isinstance(payload, dict) or payload.get("version") != TRUST_STORE_VERSION:
            return {}

        repos = payload.get("repos", {})
        if not isinstance(repos, dict):
            return {}

        records: dict[str, TrustedConfigRecord] = {}
        for key, value in repos.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            config_path = value.get("config_path")
            config_sha256 = value.get("config_sha256")
            if isinstance(config_path, str) and isinstance(config_sha256, str):
                records[key] = TrustedConfigRecord(config_path=config_path, config_sha256=config_sha256)
        return records

    def _write_records(self, records: dict[str, TrustedConfigRecord]) -> None:
        """Write the current trust records atomically with private permissions."""
        parent = self.store_path.parent
        if not _ensure_secure_directory(parent):
            return

        payload = {
            "version": TRUST_STORE_VERSION,
            "repos": {
                key: {"config_path": record.config_path, "config_sha256": record.config_sha256}
                for key, record in records.items()
            },
        }
        temp_path = parent / f".trusted_local_configs.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(temp_path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            _tighten_permissions(temp_path, 0o600)
            os.replace(temp_path, self.store_path)
            _tighten_permissions(self.store_path, 0o600)
        except Exception:
            with suppress(OSError):
                temp_path.unlink()

    def _hash_config(self, config_path: Path) -> str | None:
        """Return a stable hash for the config file contents."""
        try:
            return hashlib.sha256(config_path.read_bytes()).hexdigest()
        except Exception:
            return None

    def _is_secure_target(self, path: Path) -> bool:
        """Return True when the parent path is suitable for reads and writes."""
        return not _has_symlink_component(path)


def _tighten_permissions(path: Path, mode: int) -> None:
    """Best-effort permission hardening for cache trust paths."""
    if os.name == "nt":
        return

    with suppress(OSError):
        path.chmod(mode)


def _has_symlink_component(path: Path) -> bool:
    """Return True when path or an ancestor is a symlink."""
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


def _ensure_secure_directory(path: Path) -> bool:
    """Create a directory when possible and reject symlinked targets."""
    if _has_symlink_component(path):
        return False

    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError:
        return False

    if not path.is_dir() or _has_symlink_component(path):
        return False

    _tighten_permissions(path, 0o700)
    return True
