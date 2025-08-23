"""Cache manager for integrating with ModelAudit scanners."""

import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

from .scan_results_cache import ScanResultsCache

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manager class for integrating scan results cache with ModelAudit scanners.

    Provides a high-level interface for cache-aware scanning operations.
    """

    def __init__(self, cache_dir: Optional[str] = None, enabled: bool = True):
        """
        Initialize cache manager.

        Args:
            cache_dir: Optional cache directory path
            enabled: Whether caching is enabled
        """
        self.enabled = enabled
        self.cache = ScanResultsCache(cache_dir) if enabled else None

    def get_cached_result(self, file_path: str) -> Optional[dict[str, Any]]:
        """
        Get cached scan result if available.

        Args:
            file_path: Path to file to check cache for

        Returns:
            Cached scan result or None if not found/disabled
        """
        if not self.enabled or not self.cache:
            return None

        return self.cache.get_cached_result(file_path)

    def store_result(self, file_path: str, scan_result: dict[str, Any], scan_duration_ms: Optional[int] = None) -> None:
        """
        Store scan result in cache.

        Args:
            file_path: Path to file that was scanned
            scan_result: Scan result to cache
            scan_duration_ms: Optional scan duration
        """
        if not self.enabled or not self.cache:
            return

        self.cache.store_result(file_path, scan_result, scan_duration_ms)

    def cached_scan(self, file_path: str, scanner_func, *args, **kwargs) -> dict[str, Any]:
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
        cached_result = self.get_cached_result(file_path)

        if cached_result is not None:
            cache_lookup_time = (time.time() - start_time) * 1000
            logger.info(f"Cache HIT for {Path(file_path).name} (lookup: {cache_lookup_time:.1f}ms)")

            # Add cache metadata to result
            if isinstance(cached_result, dict):
                cached_result["_cache_info"] = {"cache_hit": True, "lookup_time_ms": cache_lookup_time}

            return cached_result

        # Cache miss - validate file exists before scanning
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        logger.info(f"Cache MISS for {Path(file_path).name} - scanning...")
        scan_start = time.time()

        try:
            scan_result = scanner_func(file_path, *args, **kwargs)
            scan_duration = (time.time() - scan_start) * 1000

            # Add cache metadata to result
            if isinstance(scan_result, dict):
                scan_result["_cache_info"] = {"cache_hit": False, "scan_duration_ms": scan_duration}

            # Store result in cache
            self.store_result(file_path, scan_result, int(scan_duration))

            return scan_result  # type: ignore[no-any-return]

        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            raise

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
        logger.info("Cache disabled")

    def enable(self, cache_dir: Optional[str] = None) -> None:
        """Enable caching."""
        self.enabled = True
        if not self.cache:
            self.cache = ScanResultsCache(cache_dir)
        logger.info("Cache enabled")


# Global cache manager instance
_global_cache_manager: Optional[CacheManager] = None


def get_cache_manager(cache_dir: Optional[str] = None, enabled: bool = True) -> CacheManager:
    """
    Get global cache manager instance.

    Args:
        cache_dir: Optional cache directory path
        enabled: Whether caching should be enabled

    Returns:
        Global cache manager instance
    """
    global _global_cache_manager

    if _global_cache_manager is None:
        _global_cache_manager = CacheManager(cache_dir, enabled)

    return _global_cache_manager


def reset_cache_manager() -> None:
    """Reset global cache manager (mainly for testing)."""
    global _global_cache_manager
    _global_cache_manager = None
