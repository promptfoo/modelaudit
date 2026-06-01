"""Unified caching decorator for ModelAudit scanning operations.

This module provides a single, consistent caching interface that eliminates
duplicate caching logic between core.py and scanners/base.py.
"""

import functools
import logging
import os
import time
from collections.abc import Callable
from typing import Any, TypeVar

from ...cache.optimized_config import get_config_extractor

logger = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

_READ_FAILURE_AWARE_CACHE_PROBE_EXTENSIONS = frozenset(
    {
        ".bin",
        ".cmf",
        ".dnn",
        ".engine",
        ".lgb",
        ".lightgbm",
        ".meta",
        ".mlmodel",
        ".npy",
        ".npz",
        ".pb",
        ".pdiparams",
        ".pdmodel",
        ".plan",
        ".rda",
        ".rdata",
        ".rds",
        ".safetensors",
        ".trt",
    }
)


def _is_read_failure_aware_scanner_path(file_path: str) -> bool:
    try:
        from ...scanners.manifest_scanner import ManifestScanner
        from ...scanners.metadata_scanner import MetadataScanner
        from ...scanners.text_scanner import TextScanner
    except Exception:
        return False

    return (
        ManifestScanner.can_handle(file_path)
        or MetadataScanner.can_handle(file_path)
        or TextScanner.can_handle(file_path)
    )


def _is_read_failure_aware_content_route(file_path: str) -> bool:
    try:
        from ..file.detection import _looks_like_renamed_r_serialized_header, read_magic_bytes
    except Exception:
        return False

    try:
        return _looks_like_renamed_r_serialized_header(read_magic_bytes(file_path, 16))
    except Exception:
        return False


def should_bypass_cache_for_read_failure_aware_file(file_path: str) -> bool:
    """Bypass stale clean cache entries for formats with explicit read-failure outcomes."""
    extension_is_read_failure_aware = (
        os.path.splitext(file_path)[1].lower() in _READ_FAILURE_AWARE_CACHE_PROBE_EXTENSIONS
    )
    return (
        extension_is_read_failure_aware
        or _is_read_failure_aware_content_route(file_path)
        or _is_read_failure_aware_scanner_path(file_path)
    )


def should_bypass_cache_for_missing_h5py(file_path: str) -> bool:
    """Bypass stale HDF5 cache entries when Keras H5 analysis is unavailable."""
    if os.path.splitext(file_path)[1].lower() not in {".h5", ".hdf5", ".keras"}:
        return False

    try:
        with open(file_path, "rb") as handle:
            if handle.read(len(_HDF5_MAGIC)) != _HDF5_MAGIC:
                return False
    except OSError:
        return False

    try:
        from ...scanners.keras_h5_scanner import HAS_H5PY
    except Exception:
        return False

    return not HAS_H5PY


def should_bypass_cache_for_safetensors_header_limit(file_path: str, config: dict[str, Any]) -> bool:
    """Do not key or store terminal bounded outcomes from oversized SafeTensors framing."""
    try:
        from ...scanners.safetensors_scanner import MAX_HEADER_BYTES
        from ..file.detection import should_defer_safetensors_header_limit_hash

        max_header_bytes = int(config.get("max_safetensors_header_bytes", MAX_HEADER_BYTES))
    except (ImportError, TypeError, ValueError):
        return False
    return should_defer_safetensors_header_limit_hash(file_path, max_header_bytes)


def _known_uncacheable_scan_result(result: Any) -> bool:
    """Return True for ScanResult objects policy will reject without serialization."""
    try:
        from ...scanner_results import INCONCLUSIVE_SCAN_OUTCOME, ScanResult, normalize_unclassified_scan_failure
    except Exception:
        return False

    if not isinstance(result, ScanResult):
        return False

    normalize_unclassified_scan_failure(result)
    metadata = result.metadata
    return (
        result.success is False
        or bool(metadata.get("operational_error"))
        or bool(metadata.get("analysis_incomplete"))
        or metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    )


def cached_scan(cache_enabled_key: str = "cache_enabled", cache_dir_key: str = "cache_dir") -> Callable[[F], F]:
    """
    Cache decorator for scan functions that take (path, config) arguments.

    This decorator provides unified caching logic that can be applied to both
    core-level scan functions and scanner-level scan methods.

    Args:
        cache_enabled_key: Config key to check if caching is enabled (default: "cache_enabled")
        cache_dir_key: Config key for cache directory (default: "cache_dir")

    Returns:
        Decorated function with caching support

    Usage:
        @cached_scan()
        def scan_file(path: str, config: Optional[dict] = None) -> ScanResult:
            return _scan_file_internal(path, config)

        @cached_scan()
        def scan(self, path: str) -> ScanResult:
            return self._actual_scan(path)
    """

    def decorator(func: F) -> F:
        # Initialize optimized config extractor once
        config_extractor = get_config_extractor()

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Use optimized configuration extraction
            cache_config, file_path = config_extractor.extract_fast(args, kwargs)

            # Fast path for disabled caching or no config
            if not cache_config or not cache_config.enabled:
                logger.debug(f"Cache disabled for {file_path}, calling function directly")
                return func(*args, **kwargs)

            # If no file path, can't cache - call directly
            if not file_path:
                logger.debug("No file path found, calling function directly")
                return func(*args, **kwargs)

            # Check if file should be cached based on characteristics
            try:
                file_stat = os.stat(file_path)
                file_ext = os.path.splitext(file_path)[1]

                if not os.access(file_path, os.R_OK):
                    logger.debug(f"Bypassing cache for unreadable file: {file_path}")
                    return func(*args, **kwargs)

                if should_bypass_cache_for_read_failure_aware_file(file_path):
                    logger.debug(f"Bypassing cache for read-failure-aware scanner: {file_path}")
                    return func(*args, **kwargs)

                if should_bypass_cache_for_missing_h5py(file_path):
                    logger.debug(f"Bypassing cache for unavailable Keras H5 analysis: {file_path}")
                    return func(*args, **kwargs)

                if not cache_config.should_cache_file(file_stat.st_size, file_ext):
                    logger.debug(f"File {file_path} not suitable for caching, calling function directly")
                    return func(*args, **kwargs)

                raw_config, _ = _extract_config_and_path(args, kwargs)
                if should_bypass_cache_for_safetensors_header_limit(file_path, raw_config or {}):
                    logger.debug(f"Bypassing cache for bounded SafeTensors header failure: {file_path}")
                    return func(*args, **kwargs)

            except OSError:
                # File doesn't exist or can't be accessed, call function directly
                logger.debug(f"Cannot access {file_path}, calling function directly")
                return func(*args, **kwargs)

            # Use cache manager for cache-enabled operations
            try:
                from ...cache import get_cache_manager
                from ...cache.cache_policy import should_cache_scan_result

                cache_manager = get_cache_manager(cache_config.cache_dir, enabled=True)
                version_context = cache_config.get_version_context()

                def cached_func_wrapper(fpath: str) -> Any:
                    """Wrapper function for cache manager"""
                    result = func(*args, **kwargs)
                    if _known_uncacheable_scan_result(result):
                        return result

                    # Convert result to dictionary format for caching
                    if hasattr(result, "to_dict"):
                        from ...scanner_results import ScanResult, normalize_unclassified_scan_failure

                        if isinstance(result, ScanResult):
                            normalize_unclassified_scan_failure(result)
                        return result.to_dict()  # type: ignore[no-any-return]
                    elif isinstance(result, dict):
                        return result
                    else:
                        # Fallback for unexpected result types
                        logger.warning(f"Unexpected result type {type(result)} for caching")
                        return {"result": str(result), "success": True}

                # Use optimized cache lookup with stat reuse
                logger.debug(f"Attempting cached scan for {file_path}")

                # Try cache first with optimized lookup
                cached_result = cache_manager.get_cached_result_with_stat(
                    file_path,
                    file_stat,
                    version_context=version_context,
                )

                if cached_result is not None:
                    logger.debug(f"Cache hit for {os.path.basename(file_path)}")
                    result_dict = cached_result
                else:
                    # Cache miss - perform scan
                    logger.debug(f"Cache miss for {os.path.basename(file_path)}, performing scan")
                    scan_start = time.perf_counter()
                    result_dict = cached_func_wrapper(file_path)
                    if not isinstance(result_dict, dict):
                        logger.debug(
                            f"Skipping cache store for known uncacheable result from {os.path.basename(file_path)}"
                        )
                        return result_dict
                    if should_cache_scan_result(result_dict):
                        scan_duration_ms = int((time.perf_counter() - scan_start) * 1000)
                        cache_manager.store_result(
                            file_path,
                            result_dict,
                            scan_duration_ms,
                            version_context=version_context,
                        )
                    else:
                        logger.debug(f"Skipping cache store for operational result from {os.path.basename(file_path)}")

                # Convert back to original type if needed
                if isinstance(result_dict, dict) and "scanner" in result_dict:
                    # This looks like a ScanResult dictionary, convert it back
                    from .result_conversion import scan_result_from_dict

                    logger.debug(f"Converting cached result back to ScanResult for {file_path}")
                    return scan_result_from_dict(result_dict)

                return result_dict

            except Exception as e:
                logger.warning(f"Cache system error for {file_path}: {e}. Falling back to direct execution.")
                return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def _extract_config_and_path(args: tuple, kwargs: dict) -> tuple[dict[str, Any] | None, str | None]:
    """
    Extract config dict and file path from function arguments.

    Supports various argument patterns:
    - func(path: str, config: dict = None)
    - func(self, path: str) where self.config exists
    - func(path: str, **kwargs) where config is in kwargs

    Args:
        args: Positional arguments
        kwargs: Keyword arguments

    Returns:
        Tuple of (config_dict, file_path)
    """
    config = None
    file_path = None

    # Try to extract file path
    if args:
        # Check if first arg looks like self (has attributes)
        if hasattr(args[0], "__dict__") and hasattr(args[0], "config"):
            # This is a method call: self.scan(path)
            config = getattr(args[0], "config", {})
            file_path = args[1] if len(args) > 1 else kwargs.get("path")
        else:
            # This is a function call: scan_file(path, config=None)
            file_path = args[0]
            config = args[1] if len(args) > 1 else kwargs.get("config")
    else:
        # All arguments are keyword arguments
        file_path = kwargs.get("path")
        config = kwargs.get("config")

    # Ensure config is a dict
    if config is None or not isinstance(config, dict):
        config = {}

    return config, file_path


def scan_with_cache(scan_func: Callable) -> Callable:
    """
    Alternative decorator for explicit caching without configuration keys.

    This is a simpler version that assumes standard config structure.

    Args:
        scan_func: The scan function to wrap with caching

    Returns:
        Cache-wrapped function
    """
    return cached_scan()(scan_func)
