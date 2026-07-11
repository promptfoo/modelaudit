"""Cache manager for integrating with ModelAudit scanners."""

import logging
import os
import time
from pathlib import Path
from typing import Any

from .adaptive_cache_keys import AdaptiveCacheKeyGenerator
from .cache_policy import cached_scan_result_dependencies_available, should_cache_scan_result
from .scan_results_cache import AncestorIdentity, ScannedFileIdentity, ScanResultsCache

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manager class for integrating scan results cache with ModelAudit scanners.

    Provides a high-level interface for cache-aware scanning operations.
    """

    def __init__(self, cache_dir: str | None = None, enabled: bool = True):
        """
        Initialize cache manager.

        Args:
            cache_dir: Optional cache directory path
            enabled: Whether caching is enabled
        """
        self.enabled = enabled
        self.cache_dir = str(Path(cache_dir).expanduser()) if cache_dir else None
        self.cache = ScanResultsCache(self.cache_dir) if enabled else None
        self.key_generator = AdaptiveCacheKeyGenerator() if enabled else None

    def get_cached_result(
        self,
        file_path: str,
        version_context: dict[str, Any] | None = None,
        *,
        include_private_metadata: bool = False,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result if available.

        Args:
            file_path: Path to file to check cache for

        Returns:
            Cached scan result or None if not found/disabled
        """
        if not self.enabled or not self.cache:
            return None

        cached_result, file_identity = self.get_cached_result_with_identity(
            file_path,
            version_context=version_context,
            include_private_metadata=include_private_metadata,
        )
        try:
            return cached_result
        finally:
            if file_identity is not None:
                self.cache.release_ancestor_identity(file_identity[-1])

    def get_cached_result_with_stat(
        self,
        file_path: str,
        stat_result: os.stat_result,
        version_context: dict[str, Any] | None = None,
        *,
        include_private_metadata: bool = False,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result using existing stat result for optimized performance.

        Args:
            file_path: Path to file to check cache for
            stat_result: Existing stat result to reuse

        Returns:
            Cached scan result or None if not found/disabled
        """
        if not self.enabled or not self.cache:
            return None

        if (
            getattr(self.get_cached_result_with_identity, "__func__", None)
            is CacheManager.get_cached_result_with_identity
        ):
            cached_result = self.cache.get_cached_result_with_stat(
                file_path,
                stat_result,
                version_context=version_context,
                include_private_metadata=include_private_metadata,
            )
            if cached_result is not None and not cached_scan_result_dependencies_available(cached_result):
                logger.debug(f"Bypassing cached result with unavailable scanner dependencies: {Path(file_path).name}")
                return None
            return cached_result

        # Preserve the established override contract for subclasses and monkeypatches.
        cached_result, file_identity = self.get_cached_result_with_identity(
            file_path,
            version_context=version_context,
            include_private_metadata=include_private_metadata,
        )
        try:
            return cached_result
        finally:
            if file_identity is not None:
                self.cache.release_ancestor_identity(file_identity[-1])

    def get_cached_result_with_identity(
        self,
        file_path: str,
        version_context: dict[str, Any] | None = None,
        *,
        include_private_metadata: bool = False,
    ) -> tuple[dict[str, Any] | None, ScannedFileIdentity | None]:
        """Return a cache lookup and retain the monitored identity for a miss scan."""
        if not self.enabled or not self.cache:
            return None, None

        cached_result, file_identity = self.cache.get_cached_result_with_identity(
            file_path,
            version_context=version_context,
            include_private_metadata=include_private_metadata,
        )
        if cached_result is not None and not cached_scan_result_dependencies_available(cached_result):
            logger.debug(f"Bypassing cached result with unavailable scanner dependencies: {Path(file_path).name}")
            return None, file_identity
        return cached_result, file_identity

    def store_result(
        self,
        file_path: str,
        scan_result: dict[str, Any],
        scan_duration_ms: int | None = None,
        version_context: dict[str, Any] | None = None,
        expected_file_stat: os.stat_result | None = None,
        expected_file_hash: str | None = None,
        expected_change_token: int | None = None,
        expected_ancestor_identity: AncestorIdentity | None = None,
    ) -> bool:
        """
        Store scan result in cache.

        Args:
            file_path: Path to file that was scanned
            scan_result: Scan result to cache
            scan_duration_ms: Optional scan duration
            version_context: Optional cache version context for config-sensitive invalidation
            expected_file_stat: File metadata captured before the scan
            expected_file_hash: Secure content hash captured before the scan
            expected_change_token: Platform-specific modification token captured before the scan
            expected_ancestor_identity: Ancestor directory identities captured before the scan
        """
        if not self.enabled or not self.cache:
            return False

        return self.cache.store_result(
            file_path,
            scan_result,
            scan_duration_ms,
            version_context=version_context,
            expected_file_stat=expected_file_stat,
            expected_file_hash=expected_file_hash,
            expected_change_token=expected_change_token,
            expected_ancestor_identity=expected_ancestor_identity,
        )

    def cached_scan(
        self,
        file_path: str,
        scanner_func: Any,
        *args: Any,
        version_context: dict[str, Any] | None = None,
        include_private_metadata: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Perform a cache-aware scan operation.

        Args:
            file_path: Path to file to scan
            scanner_func: Scanner function to call if cache miss
            *args: Arguments to pass to scanner function
            **kwargs: Keyword arguments to pass to scanner function

        Returns:
            Scan result (from cache or fresh scan)
        """
        # Try cache first
        start_time = time.time()
        pre_scan_identity: ScannedFileIdentity | None = None
        try:
            cached_result, pre_scan_identity = self.get_cached_result_with_identity(
                file_path,
                version_context=version_context,
                include_private_metadata=include_private_metadata,
            )

            if cached_result is not None:
                cache_lookup_time = (time.time() - start_time) * 1000
                logger.debug(f"Cache hit for {Path(file_path).name} (lookup: {cache_lookup_time:.1f}ms)")

                # Add cache metadata to result
                if isinstance(cached_result, dict):
                    cached_result["_cache_info"] = {"cache_hit": True, "lookup_time_ms": cache_lookup_time}

                return cached_result

            # Cache miss - validate file exists before scanning
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            logger.debug(f"Cache miss for {Path(file_path).name}, proceeding with scan")
            scan_start = time.time()
            scan_result = scanner_func(file_path, *args, **kwargs)
            scan_duration = (time.time() - scan_start) * 1000

            # Add cache metadata to result
            if isinstance(scan_result, dict):
                scan_result["_cache_info"] = {"cache_hit": False, "scan_duration_ms": scan_duration}

            cacheable_result = should_cache_scan_result(scan_result)
            if cacheable_result and pre_scan_identity is not None:
                pre_scan_stat, pre_scan_hash, pre_scan_change_token, pre_scan_ancestor_identity = pre_scan_identity
                self.store_result(
                    file_path,
                    scan_result,
                    int(scan_duration),
                    version_context=version_context,
                    expected_file_stat=pre_scan_stat,
                    expected_file_hash=pre_scan_hash,
                    expected_change_token=pre_scan_change_token,
                    expected_ancestor_identity=pre_scan_ancestor_identity,
                )
            elif not cacheable_result:
                logger.debug(f"Skipping cache store for operational result from {Path(file_path).name}")
            if isinstance(scan_result, dict) and not include_private_metadata:
                scan_result.pop("_private_metadata", None)

            return scan_result  # type: ignore[no-any-return]

        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            raise
        finally:
            if self.cache is not None and pre_scan_identity is not None:
                self.cache.release_ancestor_identity(pre_scan_identity[-1])

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        if not self.enabled or not self.cache:
            return {"enabled": False, "total_entries": 0, "hit_rate": 0.0}

        stats = self.cache.get_cache_stats()
        stats["enabled"] = True
        return stats

    def cleanup(self, max_age_days: int = 30) -> int:
        """Clean up old cache entries."""
        if not self.enabled or not self.cache:
            return 0

        return self.cache.cleanup_old_entries(max_age_days)

    def clear(self) -> None:
        """Clear entire cache."""
        if not self.enabled or not self.cache:
            return

        self.cache.clear_cache()

    def disable(self) -> None:
        """Disable caching."""
        self.enabled = False
        logger.debug("Cache disabled")

    def enable(self, cache_dir: str | None = None) -> None:
        """Enable caching."""
        self.enabled = True
        normalized_cache_dir = str(Path(cache_dir).expanduser()) if cache_dir else None
        if self.cache is None or self.cache_dir != normalized_cache_dir:
            self.cache = ScanResultsCache(normalized_cache_dir)
        if self.key_generator is None:
            self.key_generator = AdaptiveCacheKeyGenerator()
        self.cache_dir = normalized_cache_dir
        logger.debug("Cache enabled")


# Global cache manager instance
_global_cache_manager: CacheManager | None = None


def get_cache_manager(cache_dir: str | None = None, enabled: bool = True) -> CacheManager:
    """
    Get global cache manager instance.

    Args:
        cache_dir: Optional cache directory path
        enabled: Whether caching should be enabled

    Returns:
        Global cache manager instance
    """
    global _global_cache_manager
    normalized_cache_dir = str(Path(cache_dir).expanduser()) if cache_dir else None

    if _global_cache_manager is None or _global_cache_manager.cache_dir != normalized_cache_dir:
        _global_cache_manager = CacheManager(normalized_cache_dir, enabled)
    elif enabled and not _global_cache_manager.enabled:
        _global_cache_manager.enable(normalized_cache_dir)
    elif not enabled and _global_cache_manager.enabled:
        _global_cache_manager.disable()

    return _global_cache_manager


def reset_cache_manager() -> None:
    """Reset global cache manager (mainly for testing)."""
    global _global_cache_manager
    _global_cache_manager = None
