"""File-based scan results cache implementation."""

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from ..utils.secure_hasher import SecureFileHasher

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

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize the scan results cache.

        Args:
            cache_dir: Optional cache directory path. Defaults to ~/.modelaudit/cache/scan_results
        """
        self.cache_dir = Path(cache_dir or Path.home() / ".modelaudit" / "cache" / "scan_results")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.hasher = SecureFileHasher()

        self._ensure_metadata_exists()

    def get_cached_result(self, file_path: str) -> Optional[dict[str, Any]]:
        """
        Get cached scan result if available and valid with optimized file system calls.

        Args:
            file_path: Path to file to check cache for

        Returns:
            Cached scan result dictionary if found and valid, None otherwise
        """
        try:
            # Get file stats ONCE and reuse for both cache key generation and validation
            file_stat = os.stat(file_path)

            # Generate cache key with stat reuse
            cache_key = self._generate_cache_key(file_path, file_stat=file_stat)
            if not cache_key:
                return None

            # Find cache file
            cache_file_path = self._get_cache_file_path(cache_key)

            if not cache_file_path.exists():
                self._record_cache_miss("not_found")
                return None

            # Load cache entry
            with open(cache_file_path, encoding="utf-8") as f:
                cache_entry = json.load(f)

            # Validate entry is still valid (pass stat to avoid another os.stat call)
            if not self._is_cache_entry_valid_with_stat(cache_entry, file_path, file_stat):
                # Remove invalid entry
                cache_file_path.unlink()
                self._record_cache_miss("invalid")
                return None

            # Update access statistics
            cache_entry["cache_metadata"]["access_count"] += 1
            cache_entry["cache_metadata"]["last_access"] = time.time()

            # Write back updated entry
            with open(cache_file_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)

            self._record_cache_hit()
            logger.info(f"Cache HIT for {os.path.basename(file_path)}")
            return cache_entry["scan_result"]  # type: ignore[no-any-return]

        except Exception as e:
            logger.debug(f"Cache lookup failed for {file_path}: {e}")
            self._record_cache_miss("error")
            return None

    def store_result(self, file_path: str, scan_result: dict[str, Any], scan_duration_ms: Optional[int] = None) -> None:
        """
        Store scan result in cache with optimized file system calls.

        Args:
            file_path: Path to file that was scanned
            scan_result: Scan result dictionary to cache
            scan_duration_ms: Optional scan duration in milliseconds
        """
        try:
            # Get file stats ONCE and reuse
            file_stat = os.stat(file_path)

            # Pass file_stat to avoid redundant calls
            cache_key = self._generate_cache_key(file_path, file_stat=file_stat)
            if not cache_key:
                return

            # Use optimized hash method with stat reuse
            file_hash = self.hasher.hash_file_with_stat(file_path, file_stat)

            cache_entry = CacheEntry(
                cache_key=cache_key,
                file_info={
                    "hash": file_hash,
                    "size": file_stat.st_size,
                    "original_name": os.path.basename(file_path),
                    "mtime": file_stat.st_mtime,
                },
                version_info=self._get_version_info(),
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

        except Exception as e:
            logger.warning(f"Failed to cache result for {file_path}: {e}")

    def _generate_cache_key(self, file_path: str, file_stat: Optional[os.stat_result] = None) -> Optional[str]:
        """
        Generate cache key from file hash and version info.

        Args:
            file_path: Path to file
            file_stat: Optional pre-computed os.stat_result to avoid redundant calls

        Returns:
            Cache key string or None if generation failed
        """
        try:
            # Get file hash (with optional stat reuse)
            file_hash = self.hasher.hash_file_with_stat(file_path, file_stat)

            # Get version information
            version_info = self._get_version_info()

            # Create version fingerprint
            version_str = json.dumps(version_info, sort_keys=True)
            version_hash = hashlib.blake2b(version_str.encode(), digest_size=16).hexdigest()

            # Combine file hash with version hash
            # Remove any prefix from file hash for key generation
            clean_file_hash = file_hash.split(":")[-1]
            cache_key = f"{clean_file_hash}_{version_hash}"

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

    def _get_version_info(self) -> dict[str, Any]:
        """Get current version information for cache invalidation."""
        try:
            # Try to import ModelAudit version
            try:
                from modelaudit import __version__ as modelaudit_version
            except ImportError:
                modelaudit_version = "dev"

            return {
                "modelaudit_version": modelaudit_version,
                "scanner_versions": self._get_scanner_versions(),
                "config_hash": self._get_config_hash(),
            }
        except Exception as e:
            logger.debug(f"Failed to get version info: {e}")
            return {"modelaudit_version": "unknown", "scanner_versions": {}, "config_hash": "unknown"}

    def _get_scanner_versions(self) -> dict[str, str]:
        """Get version fingerprint for all scanners."""
        try:
            # Try to import scanner registry
            from modelaudit.scanners import SCANNER_REGISTRY

            versions = {}
            for name, info in SCANNER_REGISTRY.items():  # type: ignore[attr-defined]
                # Get scanner class version if available
                versions[name] = getattr(info, "version", "1.0")

            return versions
        except ImportError:
            logger.debug("Could not import scanner registry for version info")
            return {}

    def _get_config_hash(self) -> str:
        """Hash of current scanning configuration that affects results."""
        # For now, return a simple constant
        # In the future, this could include settings that affect scanning
        config_data = {"cache_version": "1.0"}

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
            cached_mtime = cache_entry["file_info"]["mtime"]
            cached_size = cache_entry["file_info"]["size"]

            # Check modification time (allow 1 second tolerance)
            if abs(file_stat.st_mtime - cached_mtime) > 1.0:
                return False

            # Check file size
            if file_stat.st_size != cached_size:
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

        logger.info(f"Cleaning up cache entries older than {max_age_days} days...")

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

        logger.info(f"Removed {removed_count} old cache entries")
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

        logger.info("Clearing entire scan results cache...")

        # Remove all cache files except metadata
        for item in self.cache_dir.iterdir():
            if item.name != "cache_metadata.json":
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        # Reset metadata
        self._create_initial_metadata()
        logger.info("Cache cleared successfully")

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

    def _record_cache_miss(self, reason: str = "unknown"):
        """Record a cache miss in statistics."""
        try:
            metadata = self._load_cache_metadata()
            metadata["statistics"]["cache_misses"] += 1

            with open(self.metadata_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to record cache miss: {e}")
