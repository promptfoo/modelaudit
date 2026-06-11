"""Unified caching decorator for ModelAudit scanning operations.

This module provides a single, consistent caching interface that eliminates
duplicate caching logic between core.py and scanners/base.py.
"""

import functools
import io
import logging
import os
import time
import zipfile
from collections.abc import Callable
from typing import Any, TypeVar

from ...cache.optimized_config import get_config_extractor
from ..file.hdf5 import find_hdf5_signature_offset

logger = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])

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


def should_bypass_cache_for_sharded_model(file_path: str) -> bool:
    """Bypass representative-only cache keys for files that can expand to sibling shards."""
    try:
        from ..file.handlers import ShardedModelDetector
    except Exception:
        return False
    return ShardedModelDetector.match_shard_filename(os.path.basename(file_path)) is not None


def should_bypass_cache_for_openvino_sidecar(file_path: str) -> bool:
    """Bypass XML-only cache keys when OpenVINO findings depend on a .bin sidecar."""
    try:
        from ...scanners.openvino_scanner import OpenVinoScanner, openvino_weights_companion_for_xml
    except Exception:
        return False

    if not OpenVinoScanner.can_handle(file_path):
        return False
    weights_path = openvino_weights_companion_for_xml(file_path)
    return weights_path is not None and (weights_path.is_file() or weights_path.is_symlink())


def _h5py_availability() -> bool:
    """Return whether Keras HDF5 analysis is available in this process."""
    try:
        from ...scanners.keras_h5_scanner import HAS_H5PY
    except Exception:
        return False

    return HAS_H5PY


def _defusedxml_availability() -> bool:
    """Return whether hardened PMML XML analysis is available in this process."""
    try:
        from ...scanners.pmml_scanner import HAS_DEFUSEDXML
    except Exception:
        return False

    return HAS_DEFUSEDXML


def add_optional_dependency_availability_to_version_context(version_context: dict[str, Any]) -> dict[str, Any]:
    """Key caches on optional dependencies that change scan coverage."""
    return {
        **version_context,
        "optional_dependency_availability": {
            "defusedxml": _defusedxml_availability(),
            "h5py": _h5py_availability(),
        },
    }


def _hdf5_h5py_availability(file_path: str) -> bool | None:
    """Return h5py availability for validated HDF5 files."""
    if find_hdf5_signature_offset(file_path) is None:
        return None
    return _h5py_availability()


def should_bypass_cache_for_missing_h5py(file_path: str) -> bool:
    """Bypass stale HDF5 cache entries when Keras H5 analysis is unavailable."""
    return _hdf5_h5py_availability(file_path) is False


def should_bypass_cache_for_unavailable_hdf5_analysis(file_path: str) -> bool:
    """Bypass HDF5 caches when the owning scanner cannot currently open the file."""
    is_hdf5 = find_hdf5_signature_offset(file_path) is not None
    has_embedded_keras_hdf5 = _has_embedded_keras_hdf5_weights(file_path)
    if not is_hdf5 and not has_embedded_keras_hdf5:
        return False
    if not _h5py_runtime_available():
        return True
    if has_embedded_keras_hdf5:
        return False

    try:
        from ...scanners.keras_h5_scanner import KerasH5Scanner

        return not KerasH5Scanner.can_handle(file_path)
    except Exception:
        return True


def should_bypass_cache_for_zip_entry_preflight(file_path: str, config: dict[str, Any]) -> bool:
    """Avoid cache probes that materialize an over-limit or inconsistent ZIP directory."""
    try:
        from ...scanner_selection import allows_zip_structure_analysis, policy_from_config
        from ...scanners.zip_scanner import ZipScanner

        if not allows_zip_structure_analysis(policy_from_config(config), file_path):
            return False
        max_entries = int(config.get("max_zip_entries", ZipScanner.DEFAULT_MAX_ENTRIES))
        max_directory_size = ZipScanner.central_directory_size_limit(config)
        return ZipScanner.requires_preflight_result(file_path, max_entries, max_directory_size)
    except (OSError, TypeError, ValueError):
        return False


def _h5py_runtime_available() -> bool:
    """Return whether h5py can create and close an in-memory HDF5 file."""
    if not _h5py_availability():
        return False
    try:
        from ...scanners.keras_h5_scanner import h5py

        with h5py.File(io.BytesIO(), "w"):
            pass
    except Exception:
        return False
    return True


def _has_embedded_keras_hdf5_weights(file_path: str) -> bool:
    """Return whether a Keras ZIP contains its standard HDF5 weights member."""
    try:
        from ...scanners.zip_scanner import ZipPreflightRejected, open_preflighted_zip
        from ..file.detection import _normalize_archive_member_name

        with open_preflighted_zip(file_path) as archive:
            member_names = {
                _normalize_archive_member_name(info.filename)
                for info in archive.infolist()
                if info.filename and not info.is_dir()
            }
    except (OSError, zipfile.BadZipFile, ZipPreflightRejected):
        return False
    return "config.json" in member_names and "model.weights.h5" in member_names


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


def should_bypass_cache_for_max_file_size(file_path: str, config: dict[str, Any], file_size: int) -> bool:
    """Bypass cache key hashing when regular scanning will reject the file size."""
    try:
        max_file_size = int(config.get("max_file_size", 0) or 0)
    except (TypeError, ValueError):
        return False
    if max_file_size <= 0 or file_size <= max_file_size:
        return False

    try:
        from ..file.handlers import should_use_advanced_handler
    except Exception:
        return True

    return not should_use_advanced_handler(file_path)


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

                if should_bypass_cache_for_sharded_model(file_path):
                    logger.debug(f"Bypassing cache for sharded model family: {file_path}")
                    return func(*args, **kwargs)

                if should_bypass_cache_for_openvino_sidecar(file_path):
                    logger.debug(f"Bypassing cache for OpenVINO sidecar-dependent scan: {file_path}")
                    return func(*args, **kwargs)

                raw_config, _ = _extract_config_and_path(args, kwargs)
                if should_bypass_cache_for_zip_entry_preflight(file_path, raw_config or {}):
                    logger.debug(f"Bypassing cache for bounded ZIP entry preflight: {file_path}")
                    return func(*args, **kwargs)

                if should_bypass_cache_for_unavailable_hdf5_analysis(file_path):
                    logger.debug(f"Bypassing cache because HDF5 analysis is unavailable: {file_path}")
                    return func(*args, **kwargs)

                if not cache_config.should_cache_file(file_stat.st_size, file_ext):
                    logger.debug(f"File {file_path} not suitable for caching, calling function directly")
                    return func(*args, **kwargs)

                if should_bypass_cache_for_safetensors_header_limit(file_path, raw_config or {}):
                    logger.debug(f"Bypassing cache for bounded SafeTensors header failure: {file_path}")
                    return func(*args, **kwargs)
                if should_bypass_cache_for_max_file_size(file_path, raw_config or {}, file_stat.st_size):
                    logger.debug(f"Bypassing cache for max_file_size rejection: {file_path}")
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
                if cache_manager.cache is None:
                    return func(*args, **kwargs)
                version_context = add_optional_dependency_availability_to_version_context(
                    cache_config.get_version_context()
                )

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
                        return result.to_dict(include_private_metadata=True)  # type: ignore[no-any-return]
                    elif isinstance(result, dict):
                        return result
                    else:
                        # Fallback for unexpected result types
                        logger.warning(f"Unexpected result type {type(result)} for caching")
                        return {"result": str(result), "success": True}

                # Use optimized cache lookup with stat reuse
                logger.debug(f"Attempting cached scan for {file_path}")

                pre_scan_identity = None
                try:
                    cached_result, pre_scan_identity = cache_manager.get_cached_result_with_identity(
                        file_path,
                        version_context=version_context,
                        include_private_metadata=True,
                    )

                    if cached_result is not None:
                        logger.debug(f"Cache hit for {os.path.basename(file_path)}")
                        result_dict = cached_result
                    else:
                        # Cache miss - perform scan
                        logger.debug(f"Cache miss for {os.path.basename(file_path)}, performing scan")
                        if pre_scan_identity is None:
                            logger.debug(f"Bypassing cache store for {file_path}: stable identity unavailable")
                            return func(*args, **kwargs)
                        pre_scan_stat, pre_scan_hash, pre_scan_change_token, pre_scan_ancestor_identity = (
                            pre_scan_identity
                        )
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
                                expected_file_stat=pre_scan_stat,
                                expected_file_hash=pre_scan_hash,
                                expected_change_token=pre_scan_change_token,
                                expected_ancestor_identity=pre_scan_ancestor_identity,
                            )
                        else:
                            logger.debug(
                                f"Skipping cache store for operational result from {os.path.basename(file_path)}"
                            )
                finally:
                    if pre_scan_identity is not None:
                        cache_manager.cache.release_ancestor_identity(pre_scan_identity[-1])

                # Convert back to original type if needed
                if isinstance(result_dict, dict) and "scanner" in result_dict:
                    # This looks like a ScanResult dictionary, convert it back
                    from .result_conversion import scan_result_from_dict

                    logger.debug(f"Converting cached result back to ScanResult for {file_path}")
                    return scan_result_from_dict(result_dict)

                result_dict.pop("_private_metadata", None)
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
