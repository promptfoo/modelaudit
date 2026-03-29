"""Optimized configuration handling for cache operations."""

import functools
import json
import threading
import time
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

CACHE_SCHEMA_VERSION = "2.0"

_CACHE_ONLY_CONFIG_KEYS = frozenset(
    {
        "cache_dir",
        "cache_enabled",
        "content_hash_threshold",
        "max_cache_file_size",
        "min_cache_file_size",
        "use_cache",
    }
)
_RUNTIME_ONLY_CONFIG_KEYS = frozenset(
    {
        "enable_progress",
        "format",
        "output",
        "progress_callback",
        "quiet",
        "show_progress",
        "verbose",
    }
)


def _serialize_fingerprint_value(value: Any) -> str:
    """Serialize a normalized value into a stable string fingerprint."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_fingerprint_value(value: Any) -> Any:
    """Normalize arbitrary values into stable, JSON-serializable structures."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            str(key): _normalize_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }

    if isinstance(value, (list, tuple)):
        return [_normalize_fingerprint_value(item) for item in value]

    if isinstance(value, (set, frozenset)):
        normalized_items = [_normalize_fingerprint_value(item) for item in value]
        return sorted(normalized_items, key=_serialize_fingerprint_value)

    if is_dataclass(value):
        normalized = {
            "__type__": f"{value.__class__.__module__}.{value.__class__.__qualname__}",
        }
        for field in fields(value):
            if field.name == "token":
                continue
            normalized[field.name] = _normalize_fingerprint_value(getattr(value, field.name))
        return normalized

    if hasattr(value, "model_dump"):
        try:
            return _normalize_fingerprint_value(value.model_dump())
        except Exception:
            pass

    if hasattr(value, "to_dict"):
        try:
            return _normalize_fingerprint_value(value.to_dict())
        except Exception:
            pass

    return repr(value)


def _normalize_cache_settings(config: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize cache-only settings used by the fast extractor and manager selection."""
    raw_config = config if isinstance(config, dict) else {}
    raw_cache_dir = raw_config.get("cache_dir")

    return {
        "cache_enabled": raw_config.get("cache_enabled", raw_config.get("use_cache", True)),
        "cache_dir": str(Path(raw_cache_dir).expanduser()) if raw_cache_dir else None,
        "content_hash_threshold": raw_config.get("content_hash_threshold", 10 * 1024 * 1024),
        "max_cache_file_size": raw_config.get("max_cache_file_size", 100 * 1024 * 1024),
        "min_cache_file_size": raw_config.get("min_cache_file_size", 1024),
    }


def normalize_material_scan_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Return the subset of scan config that can materially change findings."""
    raw_config = config if isinstance(config, dict) else {}
    normalized: dict[str, Any] = {}

    for key, value in sorted(raw_config.items(), key=lambda item: str(item[0])):
        key_str = str(key)
        if key_str in _CACHE_ONLY_CONFIG_KEYS or key_str in _RUNTIME_ONLY_CONFIG_KEYS:
            continue
        normalized[key_str] = _normalize_fingerprint_value(value)

    return normalized


def _get_rule_config_snapshot() -> dict[str, Any]:
    """Capture the active rule configuration that affects emitted findings."""
    try:
        from ..config.rule_config import get_config

        rule_config = get_config()
        return {
            "ignore": {
                pattern: sorted(codes)
                for pattern, codes in sorted(rule_config.ignore.items(), key=lambda item: item[0])
            },
            "options": _normalize_fingerprint_value(rule_config.options),
            "severity": {
                code: getattr(level, "value", str(level))
                for code, level in sorted(rule_config.severity.items(), key=lambda item: item[0])
            },
            "suppress": sorted(rule_config.suppress),
        }
    except Exception:
        return {"ignore": {}, "options": {}, "severity": {}, "suppress": []}


def build_cache_version_context(
    config: dict[str, Any] | None = None,
    *,
    normalized_scan_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable cache-version context for a scan."""
    scan_config = (
        normalized_scan_config if normalized_scan_config is not None else normalize_material_scan_config(config)
    )
    return {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "rule_config": _get_rule_config_snapshot(),
        "scan_config": scan_config,
    }


def _build_config_signature(config: dict[str, Any] | None) -> str:
    """Build a stable signature for cached CacheConfiguration objects."""
    payload = {
        "cache_settings": _normalize_cache_settings(config),
        "scan_config": normalize_material_scan_config(config),
    }
    return _serialize_fingerprint_value(payload)


class CacheConfiguration:
    """Pre-computed cache configuration to avoid repeated extraction overhead."""

    def __init__(self, config: dict[str, Any] | None = None):
        if config is None:
            config = {}

        cache_settings = _normalize_cache_settings(config)
        self.enabled = cache_settings["cache_enabled"]
        self.cache_dir = cache_settings["cache_dir"]
        self.max_file_size = cache_settings["max_cache_file_size"]
        self.min_file_size = cache_settings["min_cache_file_size"]
        self.use_content_hash_threshold = cache_settings["content_hash_threshold"]
        self._normalized_scan_config = normalize_material_scan_config(config)

        # Pre-compute common decisions
        self._small_file_extensions = {".txt", ".md", ".json", ".yaml", ".yml"}
        self._large_file_extensions = {".bin", ".pkl", ".h5", ".onnx", ".pb", ".pth", ".pt"}

    def get_version_context(self) -> dict[str, Any]:
        """Return the stable cache-version context for the current scan config."""
        return build_cache_version_context(normalized_scan_config=self._normalized_scan_config)

    @functools.lru_cache(maxsize=128)  # noqa: B019
    def should_cache_file(self, file_size: int, file_ext: str = "") -> bool:
        """
        Cached decision about whether to cache a specific file.

        Uses LRU cache to avoid repeated computation for similar files.
        """
        if not self.enabled:
            return False

        # Don't cache very small files (overhead not worth it)
        if file_size < self.min_file_size:
            return False

        # Don't cache extremely large files
        if file_size > self.max_file_size:
            return False

        # Small text files - usually not worth caching
        return not (file_ext.lower() in self._small_file_extensions and file_size < 10 * 1024)  # 10KB

    @functools.lru_cache(maxsize=64)  # noqa: B019
    def get_cache_strategy(self, file_size: int, file_ext: str = "") -> str:
        """
        Get optimal caching strategy for a file.

        Returns:
            'quick' for fast metadata-based keys
            'content' for content-hash based keys
            'none' for no caching
        """
        if not self.should_cache_file(file_size, file_ext):
            return "none"

        # Large files benefit from content hashing (deduplication)
        if file_size > self.use_content_hash_threshold:
            return "content"

        # Medium files use quick keys (balance of speed vs accuracy)
        return "quick"

    def get_performance_hint(self, file_size: int) -> dict[str, Any]:
        """Get performance hints for cache operations."""
        return {
            "use_batch_operations": file_size > 1024 * 1024,  # 1MB
            "parallel_io_recommended": file_size > 10 * 1024 * 1024,  # 10MB
            "memory_streaming_recommended": file_size > 50 * 1024 * 1024,  # 50MB
        }


class ConfigurationExtractor:
    """Optimized configuration extraction with minimal overhead."""

    def __init__(self):
        self._config_cache: dict[str, tuple[CacheConfiguration, float]] = {}
        self._result_cache: dict[tuple[str, str | None], tuple[CacheConfiguration, str | None, float]] = {}
        self._cache_expiry = 30.0  # 30 seconds
        self._last_cleanup = time.monotonic()
        self._lock = threading.RLock()

    def extract_fast(self, args: tuple, kwargs: dict) -> tuple[CacheConfiguration | None, str | None]:
        """
        Fast configuration extraction with caching.

        Returns:
            Tuple of (cache_config, file_path)
        """
        config_dict = None
        file_path = None

        # Fast path: extract file path first
        if args:
            if hasattr(args[0], "__dict__") and hasattr(args[0], "config"):
                # Method call: self.scan(path)
                config_dict = getattr(args[0], "config", {})
                file_path = args[1] if len(args) > 1 else kwargs.get("path")
            else:
                # Function call: scan_file(path, config=None)
                file_path = args[0]
                config_dict = args[1] if len(args) > 1 else kwargs.get("config")
        else:
            # Keyword arguments only
            file_path = kwargs.get("path")
            config_dict = kwargs.get("config")

        # If no file path, return minimal config
        if not file_path:
            return CacheConfiguration({}), None

        # Cache entries are keyed by a stable configuration signature so in-place
        # mutations of config dicts cannot reuse stale cache settings.
        config_key = _build_config_signature(config_dict if isinstance(config_dict, dict) else None)
        now = time.monotonic()

        with self._lock:
            # Fast path: reuse result for the same config/path combination
            result_key = (config_key, file_path)
            cached_result = self._result_cache.get(result_key)
            if cached_result and cached_result[2] > now:
                return cached_result[0], cached_result[1]

            # Reuse cached configuration if still valid
            cached_config = self._config_cache.get(config_key)
            if cached_config and (now - cached_config[1]) < self._cache_expiry:
                cache_config = cached_config[0]
            else:
                cache_config = CacheConfiguration(config_dict if isinstance(config_dict, dict) else {})
                self._config_cache[config_key] = (cache_config, now)

            expiry_time = now + self._cache_expiry
            self._result_cache[result_key] = (cache_config, file_path, expiry_time)

            # Cleanup old cache entries periodically to avoid unbounded growth
            if (len(self._config_cache) > 20 or len(self._result_cache) > 64) and (now - self._last_cleanup) > 5.0:
                self._cleanup_config_cache(current_time=now)
                self._cleanup_result_cache(current_time=now)
                self._last_cleanup = now

        return cache_config, file_path

    def _cleanup_config_cache(self, current_time: float | None = None) -> None:
        """Remove expired configuration cache entries."""
        now = current_time if current_time is not None else time.monotonic()
        with self._lock:
            expired_keys = [
                key for key, (_, timestamp) in self._config_cache.items() if now - timestamp > self._cache_expiry
            ]

            for key in expired_keys:
                del self._config_cache[key]

    def _cleanup_result_cache(self, current_time: float | None = None) -> None:
        """Remove expired cached result entries."""
        now = current_time if current_time is not None else time.monotonic()
        with self._lock:
            expired_keys = [key for key, (_, _, expiry) in self._result_cache.items() if expiry <= now]
            for key in expired_keys:
                del self._result_cache[key]


# Global extractor instance to reuse across decorators
_global_extractor = ConfigurationExtractor()


def get_config_extractor() -> ConfigurationExtractor:
    """Get global configuration extractor instance."""
    return _global_extractor
