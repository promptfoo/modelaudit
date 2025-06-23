import hashlib
import json
import os
from datetime import datetime
from typing import Any, Optional

from .. import __version__

CONFIG_DIR_ENV_VAR = "PROMPTFOO_CONFIG_DIR"
CACHE_ENABLED_ENV_VAR = "PROMPTFOO_CACHE_ENABLED"
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.promptfoo")
MODELAUDIT_SUBDIR = "modelaudit"
CACHE_FILENAME = "cache.json"

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
            if data.get("version") == __version__:
                _cache_data = data
                _cache_path = path
                return data
        except (json.JSONDecodeError, OSError):
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
    data.setdefault("entries", {})[file_hash] = {
        "file": file_path,
        "scan_time": datetime.utcnow().isoformat(),
        "result": result_dict,
    }
    save_cache()
