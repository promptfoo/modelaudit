import hashlib
import json
import os
from datetime import datetime
from typing import Any, Optional

from .. import __version__

CACHE_ENV_VAR = "MODELAUDIT_CACHE_PATH"
DISABLE_ENV_VAR = "MODELAUDIT_DISABLE_CACHE"
DEFAULT_CACHE_PATH = os.path.expanduser("~/.promptfoo/modelaudit_cache.json")

_cache_data: Optional[dict[str, Any]] = None
_cache_path: Optional[str] = None


def _get_cache_path() -> str:
    path = os.getenv(CACHE_ENV_VAR)
    if path is not None and path != "":
        return os.path.expanduser(path)
    return DEFAULT_CACHE_PATH


def _cache_disabled() -> bool:
    value = os.getenv(DISABLE_ENV_VAR, "").lower()
    return value in {"1", "true", "yes"}


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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f)
    os.replace(tmp_path, path)


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
