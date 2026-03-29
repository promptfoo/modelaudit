"""File-based scan results cache implementation."""

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..utils.helpers.secure_hasher import SecureFileHasher
from .adaptive_cache_keys import AdaptiveCacheKeyGenerator
from .optimized_config import build_cache_version_context

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Data class for cache entries."""

    cache_key: str
    file_info: dict[str, Any]
    version_info: dict[str, Any]
    scan_result: dict[str, Any]
    cache_metadata: dict[str, Any]


class ScanResultsCache:
    """
    File-based scan results cache using content hash + version for cache keys.

    Cache structure:
    ~/.modelaudit/cache/scan_results/
    ├── cache_metadata.json
    ├── ab/cd/abcd...ef.json  (hash-based file storage)
    └── xy/zw/xyzw...gh.json
    """

    def __init__(self, cache_dir: str | None = None):
        """
        Initialize the scan results cache.

        Args:
            cache_dir: Optional cache directory path. Defaults to ~/.modelaudit/cache/scan_results
        """
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache" / "scan_results")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.hasher = SecureFileHasher()
        self.key_generator = AdaptiveCacheKeyGenerator()

        self._ensure_metadata_exists()

    def get_cached_result(
        self,
        file_path: str,
        version_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result if available and valid with optimized file system calls.

        Args:
            file_path: Path to file to check cache for

        Returns:
            Cached scan result dictionary if found and valid, None otherwise
        """
        try:
            file_stat = os.stat(file_path)
        except OSError as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._record_cache_miss("error")
            return None

        return self._get_cached_result_with_known_stat(file_path, file_stat, version_context)

    def get_cached_result_with_stat(
        self,
        file_path: str,
        file_stat: os.stat_result,
        version_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """
        Get a cached scan result while reusing an existing stat result.

        Args:
            file_path: Path to file to check cache for
            file_stat: Pre-computed os.stat_result to reuse
            version_context: Optional cache version context for config-sensitive invalidation

        Returns:
            Cached scan result dictionary if found and valid, None otherwise
        """
        return self._get_cached_result_with_known_stat(file_path, file_stat, version_context)

    def _get_cached_result_with_known_stat(
        self,
        file_path: str,
        file_stat: os.stat_result,
        version_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Load and validate a cache entry using a caller-provided stat result."""
        try:
            cache_key = self._generate_cache_key(file_path, file_stat=file_stat, version_context=version_context)
            if not cache_key:
                return None

            cache_file_path = self._get_cache_file_path(cache_key)
            if not cache_file_path.exists():
                self._record_cache_miss("not_found")
                return None

            with open(cache_file_path, encoding="utf-8") as f:
                cache_entry = json.load(f)

            if not self._is_cache_entry_valid_with_stat(cache_entry, file_path, file_stat):
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None

            cache_entry["cache_metadata"]["access_count"] += 1
            cache_entry["cache_metadata"]["last_access"] = time.time()

            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)

            self._record_cache_hit()
            logger.debug(f"Cache hit for {os.path.basename(file_path)}")
            return cache_entry["scan_result"]  # type: ignore[no-any-return]

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._record_cache_miss("error")
            return None

    def get_cached_result_by_key(
        self,
        cache_key: str,
        *,
        file_path: str | None = None,
        file_stat: os.stat_result | None = None,
    ) -> dict[str, Any] | None:
        """
        Get cached scan result by pre-generated cache key (for performance optimization).

        Args:
            cache_key: Pre-generated cache key

        Returns:
            Cached scan result dictionary if found, None otherwise
        """
        return self._get_cached_result_by_key(cache_key, file_path=file_path, file_stat=file_stat)

    def _get_cached_result_by_key(
        self,
        cache_key: str,
        file_path: str | None = None,
        file_stat: os.stat_result | None = None,
    ) -> dict[str, Any] | None:
        """Get a cached result using a precomputed key, optionally validating with caller-provided stat data."""
        try:
            cache_file_path = self._get_cache_file_path(cache_key)

            if not cache_file_path.exists():
                self._record_cache_miss("not_found")
                return None

            # Load cache entry
            with open(cache_file_path, encoding="utf-8") as f:
                cache_entry = json.load(f)

            if (
                file_path is not None
                and file_stat is not None
                and not self._is_cache_entry_valid_with_stat(cache_entry, file_path, file_stat)
            ):
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None

            # Update access statistics
            cache_entry["cache_metadata"]["access_count"] += 1
            cache_entry["cache_metadata"]["last_access"] = time.time()

            # Write back updated entry (async write would be better but adds complexity)
            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)

            self._record_cache_hit()
            logger.debug(f"Cache hit for key {cache_key[:8]}...")
            return cache_entry["scan_result"]  # type: ignore[no-any-return]

        except Exception as e:
            logger.debug(f"Cache lookup failed for key {cache_key[:8]}...: {e}")
            self._record_cache_miss("error")
            return None

    def store_result(
        self,
        file_path: str,
        scan_result: dict[str, Any],
        scan_duration_ms: int | None = None,
        version_context: dict[str, Any] | None = None,
    ) -> bool:
        """
        Store scan result in cache with optimized file system calls.

        Args:
            file_path: Path to file that was scanned
            scan_result: Scan result dictionary to cache
            scan_duration_ms: Optional scan duration in milliseconds
        Returns:
            True when a cache entry was persisted, False when storage was skipped or failed.
        """
        try:
            # Get file stats ONCE and reuse
            file_stat = os.stat(file_path)
            version_info = self._get_version_info(version_context)
            if version_info is None:
                return False

            # Pass file_stat to avoid redundant calls
            cache_key = self._generate_cache_key(
                file_path,
                file_stat=file_stat,
                version_context=version_context,
                version_info=version_info,
            )
            if not cache_key:
                return False

            # Use optimized hash method with stat reuse
            file_hash = self.hasher.hash_file_with_stat(file_path, file_stat)
            mtime_ns = getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000))

            cache_entry = CacheEntry(
                cache_key=cache_key,
                file_info={
                    "hash": file_hash,
                    "size": file_stat.st_size,
                    "original_name": os.path.basename(file_path),
                    "mtime": file_stat.st_mtime,
                    "mtime_ns": mtime_ns,
                },
                version_info=version_info,
                scan_result=scan_result,
                cache_metadata={
                    "scanned_at": time.time(),
                    "last_access": time.time(),
                    "access_count": 1,
                    "scan_duration_ms": scan_duration_ms,
                    "file_format": self._detect_file_format(file_path),
                },
            )

            # Save cache entry
            cache_file_path = self._get_cache_file_path(cache_key)
            cache_file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(asdict(cache_entry), f, indent=2)

            logger.debug(f"Cached scan result for {os.path.basename(file_path)}")
            return True

        except Exception as e:
            logger.debug(f"Failed to cache result for {file_path}: {e}")
            return False

    def generate_cache_key(
        self,
        file_path: str,
        file_stat: os.stat_result | None = None,
        version_context: dict[str, Any] | None = None,
        version_info: dict[str, Any] | None = None,
    ) -> str | None:
        """Public wrapper for cache key generation used by higher-level cache callers."""
        return self._generate_cache_key(
            file_path,
            file_stat=file_stat,
            version_context=version_context,
            version_info=version_info,
        )

    def _generate_cache_key(
        self,
        file_path: str,
        file_stat: os.stat_result | None = None,
        version_context: dict[str, Any] | None = None,
        version_info: dict[str, Any] | None = None,
    ) -> str | None:
        """
        Generate cache key from file hash and version info.

        Args:
            file_path: Path to file
            file_stat: Optional pre-computed os.stat_result to avoid redundant calls

        Returns:
            Cache key string or None if generation failed
        """
        try:
            if file_stat is not None:
                file_key = self.key_generator.generate_key_with_stat_reuse(file_path, file_stat)
            else:
                file_key = self.key_generator.generate_key(file_path)

            resolved_version_info = (
                version_info if version_info is not None else self._get_version_info(version_context)
            )
            if resolved_version_info is None:
                return None

            # Create version fingerprint
            version_str = json.dumps(resolved_version_info, sort_keys=True)
            version_hash = hashlib.blake2b(version_str.encode(), digest_size=16).hexdigest()

            # Combine file hash with version hash
            # Remove any prefix from file hash for key generation
            clean_file_key = file_key.split(":")[-1]
            cache_key = f"{clean_file_key}_{version_hash}"

            return cache_key

        except Exception as e:
            logger.debug(f"Failed to generate cache key for {file_path}: {e}")
            return None

    def _get_cache_file_path(self, cache_key: str) -> Path:
        """
        Get file system path for cache key using hash-based directory structure.

        Args:
            cache_key: Cache key string

        Returns:
            Path to cache file
        """
        # Create nested directory structure: ab/cd/cache_key.json
        # This prevents too many files in a single directory
        return self.cache_dir / cache_key[:2] / cache_key[2:4] / f"{cache_key}.json"

    def _get_version_info(self, version_context: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Get current version information for cache invalidation.

        Returns None when a material component cannot be resolved, signalling
        that caching must be skipped to avoid key collisions.
        """
        try:
            from modelaudit import __version__ as modelaudit_version
        except ImportError:
            modelaudit_version = "dev"
        except Exception as e:
            logger.debug(f"Failed to resolve modelaudit version: {e}")
            modelaudit_version = "unknown"

        try:
            config_hash = self._get_config_hash(version_context)
        except Exception as e:
            logger.debug(f"Failed to compute cache config hash, disabling cache for this key: {e}")
            return None

        try:
            scanner_versions = self._get_scanner_versions()
        except Exception as e:
            logger.debug(f"Failed to resolve scanner versions, disabling cache for this key: {e}")
            return None

        return {
            "modelaudit_version": modelaudit_version,
            "scanner_versions": scanner_versions,
            "config_hash": config_hash,
        }

    def _get_scanner_versions(self) -> dict[str, str]:
        """Get version fingerprint for all scanners."""
        from modelaudit.scanners import _registry

        versions = {}
        for scanner_id in sorted(_registry.get_available_scanners()):
            info = _registry.get_scanner_info(scanner_id) or {}
            versions[scanner_id] = str(info.get("version", "1.0"))

        return versions

    def _get_config_hash(self, version_context: dict[str, Any] | None = None) -> str:
        """Hash of current scanning configuration that affects results."""
        config_data = version_context or build_cache_version_context()

        config_str = json.dumps(config_data, sort_keys=True)
        return hashlib.blake2b(config_str.encode(), digest_size=8).hexdigest()

    def _is_cache_entry_valid(self, cache_entry: dict[str, Any], file_path: str) -> bool:
        """
        Validate that cache entry is still valid.

        Args:
            cache_entry: Cache entry dictionary
            file_path: Current file path

        Returns:
            True if entry is valid, False otherwise
        """
        current_stat = os.stat(file_path)
        return self._is_cache_entry_valid_with_stat(cache_entry, file_path, current_stat)

    def _is_cache_entry_valid_with_stat(
        self, cache_entry: dict[str, Any], file_path: str, file_stat: os.stat_result
    ) -> bool:
        """
        Validate that cache entry is still valid with stat reuse.

        Args:
            cache_entry: Cache entry dictionary
            file_path: Current file path
            file_stat: Pre-computed os.stat_result

        Returns:
            True if entry is valid, False otherwise
        """
        try:
            # Check file hasn't changed
            cached_mtime_ns = cache_entry["file_info"].get("mtime_ns")
            cached_size = cache_entry["file_info"]["size"]
            current_mtime_ns = getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1_000_000_000))

            if cached_mtime_ns is None:
                cached_mtime_ns = int(float(cache_entry["file_info"]["mtime"]) * 1_000_000_000)

            if int(cached_mtime_ns) != current_mtime_ns:
                return False

            # Check file size
            if file_stat.st_size != cached_size:
                return False

            # Metadata-only cache keys must still validate file contents, or an
            # in-place rewrite that restores size/mtime can hit stale entries.
            if not self.key_generator._should_use_content_hash(file_stat.st_size):
                cached_hash = cache_entry["file_info"].get("hash")
                if cached_hash is not None:
                    current_hash = self.hasher.hash_file_with_stat(file_path, file_stat)
                    if current_hash != cached_hash:
                        return False

            # Check entry isn't too old (30 days default)
            scanned_at = cache_entry["cache_metadata"]["scanned_at"]
            age_days = (time.time() - scanned_at) / (24 * 60 * 60)

            return not age_days > 30

        except Exception:
            return False

    def _detect_file_format(self, file_path: str) -> str:
        """Detect file format for analytics."""
        extension = Path(file_path).suffix.lower()

        format_map = {
            ".pkl": "pickle",
            ".pickle": "pickle",
            ".pt": "pytorch",
            ".pth": "pytorch",
            ".bin": "pytorch",
            ".h5": "keras",
            ".keras": "keras",
            ".pb": "tensorflow",
            ".onnx": "onnx",
            ".safetensors": "safetensors",
        }

        return format_map.get(extension, "unknown")

    def cleanup_old_entries(self, max_age_days: int = 30) -> int:
        """
        Clean up old cache entries.

        Args:
            max_age_days: Maximum age in days for cache entries

        Returns:
            Number of entries removed
        """
        removed_count = 0
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)

        logger.debug(f"Cleaning cache entries older than {max_age_days} days")

        # Walk through all cache files
        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name == "cache_metadata.json":
                continue

            try:
                with open(cache_file, encoding="utf-8") as f:
                    cache_entry = json.load(f)

                last_access = cache_entry["cache_metadata"]["last_access"]

                if last_access < cutoff_time:
                    cache_file.unlink()
                    removed_count += 1

            except Exception as e:
                logger.debug(f"Error processing cache file {cache_file}: {e}")
                # Remove corrupted cache files
                cache_file.unlink()
                removed_count += 1

        # Clean up empty directories
        self._cleanup_empty_directories()

        logger.debug(f"Removed {removed_count} old cache entries")
        return removed_count

    def _cleanup_empty_directories(self):
        """Remove empty cache subdirectories."""
        for root, dirs, _files in os.walk(self.cache_dir, topdown=False):
            for dirname in dirs:
                dir_path = Path(root) / dirname
                try:
                    if not any(dir_path.iterdir()):
                        dir_path.rmdir()
                except OSError:
                    pass  # Directory not empty or other error

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        try:
            metadata = self._load_cache_metadata()

            # Count current entries
            total_files = len(list(self.cache_dir.rglob("*.json"))) - 1  # Exclude metadata file

            # Calculate disk usage
            total_size = sum(f.stat().st_size for f in self.cache_dir.rglob("*") if f.is_file())

            stats = metadata.get("statistics", {})
            cache_hits = stats.get("cache_hits", 0)
            cache_misses = stats.get("cache_misses", 0)

            hit_rate = cache_hits / (cache_hits + cache_misses) if (cache_hits + cache_misses) > 0 else 0.0

            return {
                "total_entries": total_files,
                "total_size_mb": total_size / (1024 * 1024),
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
                "hit_rate": hit_rate,
                "avg_scan_time_ms": stats.get("avg_scan_time_ms", 0.0),
            }
        except Exception as e:
            logger.warning(f"Failed to get cache stats: {e}")
            return {
                "total_entries": 0,
                "total_size_mb": 0.0,
                "cache_hits": 0,
                "cache_misses": 0,
                "hit_rate": 0.0,
                "avg_scan_time_ms": 0.0,
            }

    def clear_cache(self) -> None:
        """Clear entire cache."""
        import shutil

        logger.debug("Clearing entire scan results cache")

        # Remove all cache files except metadata
        for item in self.cache_dir.iterdir():
            if item.name != "cache_metadata.json":
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        # Reset metadata
        self._create_initial_metadata()
        logger.debug("Cache cleared successfully")

    def _ensure_metadata_exists(self):
        """Ensure cache metadata file exists."""
        if not self.metadata_file.exists():
            self._create_initial_metadata()

    def _create_initial_metadata(self):
        """Create initial cache metadata."""
        metadata = {
            "version": "1.0",
            "created_at": time.time(),
            "last_cleanup": time.time(),
            "statistics": {"total_entries": 0, "cache_hits": 0, "cache_misses": 0, "avg_scan_time_ms": 0.0},
            "settings": {"max_entries": 100000, "max_age_days": 30, "cleanup_threshold": 0.9},
        }

        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

    def _load_cache_metadata(self) -> dict[str, Any]:
        """Load cache metadata from file."""
        try:
            with open(self.metadata_file, encoding="utf-8") as f:
                return json.load(f)  # type: ignore[no-any-return]
        except Exception:
            # Return default metadata if file can't be loaded
            return {"statistics": {"cache_hits": 0, "cache_misses": 0, "avg_scan_time_ms": 0.0}}

    def _record_cache_hit(self):
        """Record a cache hit in statistics."""
        try:
            metadata = self._load_cache_metadata()
            metadata["statistics"]["cache_hits"] += 1

            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to record cache hit: {e}")

    def _record_cache_miss(self, reason: str = "unknown") -> None:
        """Record a cache miss in statistics."""
        try:
            metadata = self._load_cache_metadata()
            metadata["statistics"]["cache_misses"] += 1

            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to record cache miss: {e}")
