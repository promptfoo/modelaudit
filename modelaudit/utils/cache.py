import hashlib
import json
import os
from datetime import datetime
from typing import Any, Optional

from .. import __version__

CONFIG_DIR_ENV_VAR = "PROMPTFOO_CONFIG_DIR"
CACHE_ENABLED_ENV_VAR = "PROMPTFOO_CACHE_ENABLED"
CACHE_MAX_FILE_COUNT_ENV_VAR = "PROMPTFOO_CACHE_MAX_FILE_COUNT"
CACHE_MAX_SIZE_ENV_VAR = "PROMPTFOO_CACHE_MAX_SIZE"
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.promptfoo")
MODELAUDIT_SUBDIR = "modelaudit"
CACHE_FILENAME = "cache.json"
DEFAULT_MAX_CACHE_ENTRIES = 1000  # Default file count limit
DEFAULT_MAX_CACHE_SIZE = 100 * 1024 * 1024  # Default 100MB cache size limit

_cache_data: Optional[dict[str, Any]] = None
_cache_path: Optional[str] = None


def _get_cache_path() -> str:
    config_dir = os.getenv(CONFIG_DIR_ENV_VAR)
    if config_dir is not None and config_dir != "":
        config_dir = os.path.expanduser(config_dir)
    else:
        config_dir = DEFAULT_CONFIG_DIR

    # Always use the modelaudit subdirectory
    cache_dir = os.path.join(config_dir, MODELAUDIT_SUBDIR)
    return os.path.join(cache_dir, CACHE_FILENAME)


def _cache_disabled() -> bool:
    value = os.getenv(CACHE_ENABLED_ENV_VAR, "true").lower()
    return value in {"0", "false", "no", "off"}


def _get_max_cache_entries() -> int:
    try:
        return int(
            os.getenv(CACHE_MAX_FILE_COUNT_ENV_VAR, str(DEFAULT_MAX_CACHE_ENTRIES))
        )
    except ValueError:
        return DEFAULT_MAX_CACHE_ENTRIES


def _get_max_cache_size() -> int:
    try:
        return int(os.getenv(CACHE_MAX_SIZE_ENV_VAR, str(DEFAULT_MAX_CACHE_SIZE)))
    except ValueError:
        return DEFAULT_MAX_CACHE_SIZE


def _calculate_cache_size(entries: dict[str, Any]) -> int:
    """Calculate approximate cache size in bytes."""
    # Rough estimation: JSON size of the entries
    try:
        return len(json.dumps(entries).encode("utf-8"))
    except (TypeError, ValueError):
        # Fallback: estimate based on entry count
        return len(entries) * 1024  # Assume 1KB per entry average


def load_cache() -> dict[str, Any]:
    global _cache_data, _cache_path
    path = _get_cache_path()

    if _cache_data is not None and _cache_path == path:
        return _cache_data

    if _cache_disabled():
        _cache_data = {"version": __version__, "entries": {}}
        _cache_path = path
        return _cache_data

    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            # Validate cache structure
            if (
                not isinstance(data, dict)
                or "version" not in data
                or "entries" not in data
            ):
                # Invalid cache structure, recreate
                pass
            elif data.get("version") == __version__:
                _cache_data = data
                _cache_path = path
                return data
        except (json.JSONDecodeError, OSError, TypeError):
            # Cache file is corrupted or unreadable, will recreate
            pass

    _cache_data = {"version": __version__, "entries": {}}
    _cache_path = path
    return _cache_data


def save_cache() -> None:
    if _cache_disabled():
        return
    data = load_cache()
    path = _get_cache_path()
    # Ensure directory exists with more robust error handling
    dir_path = os.path.dirname(path)
    try:
        os.makedirs(dir_path, exist_ok=True)
    except OSError:
        # If we can't create the directory, skip caching
        return

    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
    except OSError:
        # If we can't write the cache file, clean up and skip
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def compute_sha256(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_cached_result(file_hash: str) -> Optional[dict[str, Any]]:
    data = load_cache()
    return data.get("entries", {}).get(file_hash)


def update_cache(file_hash: str, file_path: str, result: Any) -> None:
    if _cache_disabled():
        return
    data = load_cache()
    if isinstance(result, dict):
        result_dict = result
    else:
        result_dict = result.to_dict()

    entries = data.setdefault("entries", {})
    max_entries = _get_max_cache_entries()
    max_size = _get_max_cache_size()

    # Add the new entry first
    new_entry = {
        "file": file_path,
        "scan_time": datetime.utcnow().isoformat(),
        "result": result_dict,
    }
    entries[file_hash] = new_entry

    # Check both file count and size limits
    needs_cleanup = (
        len(entries) > max_entries or _calculate_cache_size(entries) > max_size
    )

    if needs_cleanup:
        # Sort entries by scan_time (oldest first)
        sorted_entries = sorted(
            entries.items(),
            key=lambda x: x[1].get("scan_time", ""),
        )

        # Remove oldest entries until both limits are satisfied
        # Remove at least 10% or enough to get under limits
        min_remove = max(1, len(entries) // 10)
        removed_count = 0

        for old_hash, _ in sorted_entries:
            # Don't remove the entry we just added
            if old_hash == file_hash:
                continue

            del entries[old_hash]
            removed_count += 1

            # Check if we've satisfied both limits
            if (
                removed_count >= min_remove
                and len(entries) <= max_entries
                and _calculate_cache_size(entries) <= max_size
            ):
                break

    save_cache()
