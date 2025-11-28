"""Batch cache operations for optimized multi-file scanning."""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .cache_manager import CacheManager
from .smart_cache_keys import SmartCacheKeyGenerator

logger = logging.getLogger(__name__)


class BatchCacheOperations:
    """Optimized batch operations for cache management."""

    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.key_generator = cache_manager.key_generator or SmartCacheKeyGenerator()

    def batch_lookup(self, file_paths: list[str], max_workers: int = 4) -> dict[str, dict[str, Any] | None]:
        """
        Perform batch cache lookups with I/O optimization.

        Groups cache files by directory for efficient I/O and uses
        concurrent reads to improve performance.

        Args:
            file_paths: List of file paths to look up
            max_workers: Maximum number of concurrent I/O operations

        Returns:
            Dictionary mapping file paths to cached results (or None if not cached)
        """
        if not self.cache_manager.enabled or not self.cache_manager.cache:
            return dict.fromkeys(file_paths)

        results: dict[str, dict[str, Any] | None] = {}
        cache_lookups = []

        # Prepare cache lookups with stat collection
        for file_path in file_paths:
            try:
                stat_result = os.stat(file_path)
                cache_key = self.key_generator.generate_key_with_stat_reuse(file_path, stat_result)
                cache_lookups.append((file_path, cache_key, stat_result))
            except OSError as e:
                logger.debug(f"Failed to stat {file_path}: {e}")
                results[file_path] = None

        # Group by cache directory for efficient I/O
        cache_dir_groups = self._group_by_cache_directory(cache_lookups)

        # Process each cache directory concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_group = {
                executor.submit(self._process_cache_directory_group, group_files): group_files
                for group, group_files in cache_dir_groups.items()
            }

            for future in as_completed(future_to_group):
                group_files = future_to_group[future]
                try:
                    group_results = future.result()
                    results.update(group_results)
                except Exception as e:
                    logger.warning(f"Failed to process cache directory group: {e}")
                    # Mark all files in this group as cache miss
                    for file_path, _, _ in group_files:
                        results[file_path] = None

        # Fill in any missing results
        for file_path in file_paths:
            if file_path not in results:
                results[file_path] = None

        logger.debug(f"Batch lookup complete: {len(results)} files processed")
        return results

    def _group_by_cache_directory(
        self, cache_lookups: list[tuple[str, str, os.stat_result]]
    ) -> dict[Path, list[tuple[str, str, os.stat_result]]]:
        """Group cache lookups by cache directory for efficient I/O."""
        groups: dict[Path, list[tuple[str, str, os.stat_result]]] = {}

        for file_path, cache_key, stat_result in cache_lookups:
            if self.cache_manager.cache is not None:
                cache_file_path = self.cache_manager.cache._get_cache_file_path(cache_key)
                cache_dir = cache_file_path.parent
            else:
                # Fallback grouping by file directory if no cache
                cache_dir = Path(file_path).parent

            if cache_dir not in groups:
                groups[cache_dir] = []
            groups[cache_dir].append((file_path, cache_key, stat_result))

        return groups

    def _process_cache_directory_group(
        self, group_files: list[tuple[str, str, os.stat_result]]
    ) -> dict[str, dict[str, Any] | None]:
        """Process all cache files in a single directory efficiently."""
        results: dict[str, dict[str, Any] | None] = {}

        for file_path, cache_key, _stat_result in group_files:
            try:
                # Use optimized cache lookup
                if self.cache_manager.cache is not None:
                    cached_result = self.cache_manager.cache.get_cached_result_by_key(cache_key)
                else:
                    cached_result = None
                results[file_path] = cached_result

                if cached_result:
                    logger.debug(f"Batch cache hit: {os.path.basename(file_path)}")
                else:
                    logger.debug(f"Batch cache miss: {os.path.basename(file_path)}")

            except Exception as e:
                logger.debug(f"Batch cache lookup failed for {file_path}: {e}")
                results[file_path] = None

        return results

    def batch_store(self, scan_results: list[tuple[str, dict[str, Any], int | None]], max_workers: int = 2) -> int:
        """
        Store multiple scan results in cache with batch optimization.

        Args:
            scan_results: List of (file_path, scan_result, scan_duration_ms) tuples
            max_workers: Maximum number of concurrent I/O operations

        Returns:
            Number of successfully stored results
        """
        if not self.cache_manager.enabled or not self.cache_manager.cache:
            return 0

        stored_count = 0

        # Use moderate concurrency for write operations (less than reads)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(self._store_single_result, file_path, scan_result, scan_duration_ms): file_path
                for file_path, scan_result, scan_duration_ms in scan_results
            }

            for future in as_completed(future_to_path):
                file_path = future_to_path[future]
                try:
                    success = future.result()
                    if success:
                        stored_count += 1
                        logger.debug(f"Batch stored: {os.path.basename(file_path)}")
                    else:
                        logger.debug(f"Batch store failed: {os.path.basename(file_path)}")
                except Exception as e:
                    logger.warning(f"Failed to store cache result for {file_path}: {e}")

        logger.debug(f"Batch store complete: {stored_count}/{len(scan_results)} results stored")
        return stored_count

    def _store_single_result(self, file_path: str, scan_result: dict[str, Any], scan_duration_ms: int | None) -> bool:
        """Store a single result and return success status."""
        try:
            self.cache_manager.store_result(file_path, scan_result, scan_duration_ms)
            return True
        except Exception as e:
            logger.debug(f"Failed to store result for {file_path}: {e}")
            return False

    def prefetch_cache_metadata(self, file_paths: list[str]) -> None:
        """
        Prefetch cache metadata for upcoming operations.

        This can warm up the cache manager's internal caches
        and improve subsequent operation performance.
        """
        if not self.cache_manager.enabled or not self.cache_manager.key_generator:
            return

        # Warm up the key generator's fingerprint cache
        for file_path in file_paths[:50]:  # Limit to avoid memory bloat
            try:
                stat_result = os.stat(file_path)
                # This will cache the fingerprint
                self.cache_manager.key_generator.generate_key_with_stat_reuse(file_path, stat_result)
            except OSError:
                continue

        logger.debug(f"Prefetched cache metadata for {len(file_paths)} files")

    def get_batch_stats(self) -> dict[str, Any]:
        """Get performance statistics for batch operations."""
        if not self.cache_manager.enabled or not self.cache_manager.key_generator:
            return {"enabled": False}

        key_gen_stats = self.cache_manager.key_generator.get_performance_stats()
        cache_stats = self.cache_manager.get_stats()

        return {
            "enabled": True,
            "key_generation": key_gen_stats,
            "cache_stats": cache_stats,
        }
