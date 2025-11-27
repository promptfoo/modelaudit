"""Smart cache key generation with optimized performance.

This module provides efficient cache key generation that avoids redundant
file system calls and provides intelligent key selection based on file characteristics.
"""

import hashlib
import os
import time
from dataclasses import dataclass

from ..utils.helpers.secure_hasher import SecureFileHasher


@dataclass
class FileFingerprint:
    """Lightweight file fingerprint for efficient cache key generation."""

    path_hash: str
    size: int
    mtime: float
    inode: int
    content_hash: str | None = None  # Lazy-loaded for large files

    @classmethod
    def from_stat(cls, file_path: str, stat_result: os.stat_result) -> "FileFingerprint":
        """Create fingerprint from existing stat result to avoid redundant syscalls."""
        # Use blake2b for fast path hashing (much faster than sha256)
        path_hash = hashlib.blake2b(file_path.encode(), digest_size=8).hexdigest()

        return cls(path_hash=path_hash, size=stat_result.st_size, mtime=stat_result.st_mtime, inode=stat_result.st_ino)

    @classmethod
    def from_path(cls, file_path: str) -> "FileFingerprint":
        """Create fingerprint with single stat call."""
        stat_result = os.stat(file_path)
        return cls.from_stat(file_path, stat_result)

    def quick_key(self) -> str:
        """Generate fast cache key without content hash (for small files)."""
        return f"{self.path_hash}_{self.size}_{int(self.mtime)}_{self.inode}"

    def secure_key(self, file_path: str, hasher: SecureFileHasher | None = None) -> str:
        """Generate secure cache key with content hash (lazy-loaded)."""
        if self.content_hash is None:
            if hasher is None:
                hasher = SecureFileHasher()
            self.content_hash = hasher.hash_file(file_path)

        return f"{self.quick_key()}_{self.content_hash}"


class SmartCacheKeyGenerator:
    """Optimized cache key generation with intelligent key selection."""

    # Thresholds for cache key strategy
    CONTENT_HASH_THRESHOLD = 10 * 1024 * 1024  # 10MB - use content hash for larger files
    QUICK_KEY_MAX_SIZE = 1 * 1024 * 1024  # 1MB - quick keys for small files

    def __init__(self):
        self.hasher = SecureFileHasher()
        self.fingerprint_cache = {}  # Brief cache for repeated operations
        self.cache_expiry = 5.0  # Cache fingerprints for 5 seconds

    def generate_key_with_stat_reuse(self, file_path: str, stat_result: os.stat_result) -> str:
        """Generate cache key reusing existing stat result for optimal performance."""
        fingerprint = FileFingerprint.from_stat(file_path, stat_result)

        # Use content hash strategy based on file size
        if self._should_use_content_hash(stat_result.st_size):
            secure_key = fingerprint.secure_key(file_path, self.hasher)
            return str(secure_key)
        else:
            quick_key = fingerprint.quick_key()
            return str(quick_key)

    def generate_key(self, file_path: str) -> str:
        """Generate cache key with smart strategy selection."""
        # Check if we have a recent fingerprint cached
        cache_key = f"fp_{file_path}"
        current_time = time.time()

        if cache_key in self.fingerprint_cache:
            fingerprint, cached_time = self.fingerprint_cache[cache_key]
            if current_time - cached_time < self.cache_expiry:
                # Use cached fingerprint - avoid redundant stat calls
                if self._should_use_content_hash(fingerprint.size):
                    secure_key = fingerprint.secure_key(file_path, self.hasher)
                    return str(secure_key)
                else:
                    quick_key = fingerprint.quick_key()
                    return str(quick_key)

        # Create new fingerprint
        fingerprint = FileFingerprint.from_path(file_path)

        # Cache briefly for potential reuse
        self.fingerprint_cache[cache_key] = (fingerprint, current_time)

        # Clean old cache entries periodically
        if len(self.fingerprint_cache) > 100:
            self._cleanup_fingerprint_cache(current_time)

        # Generate appropriate key type
        if self._should_use_content_hash(fingerprint.size):
            secure_key = fingerprint.secure_key(file_path, self.hasher)
            return str(secure_key)
        else:
            quick_key = fingerprint.quick_key()
            return str(quick_key)

    def _should_use_content_hash(self, file_size: int) -> bool:
        """Decide whether to use expensive content hash based on file characteristics."""
        # Very small files: quick key (overhead not worth it)
        if file_size < self.QUICK_KEY_MAX_SIZE:
            return False

        # Large files: content hash (caching provides significant benefit)
        # Medium files: quick key (balance between accuracy and performance)
        return file_size > self.CONTENT_HASH_THRESHOLD

    def _cleanup_fingerprint_cache(self, current_time: float) -> None:
        """Remove expired fingerprint cache entries."""
        expired_keys = [
            key
            for key, (_, cached_time) in self.fingerprint_cache.items()
            if current_time - cached_time > self.cache_expiry
        ]

        for key in expired_keys:
            del self.fingerprint_cache[key]

    def get_performance_stats(self) -> dict:
        """Get performance statistics for monitoring."""
        return {
            "cached_fingerprints": len(self.fingerprint_cache),
            "content_hash_threshold_mb": self.CONTENT_HASH_THRESHOLD / (1024 * 1024),
            "quick_key_max_size_mb": self.QUICK_KEY_MAX_SIZE / (1024 * 1024),
        }
