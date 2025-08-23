"""Secure file hashing for ModelAudit cache system."""

import hashlib
import logging
import mmap
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


class SecureFileHasher:
    """
    Production-ready secure file hashing for ModelAudit cache system.

    Uses Blake2b for cryptographic security with optimal performance.
    Handles files of any size with streaming approach.
    """

    def __init__(self, full_hash_threshold: int = 2 * 1024**3):
        """
        Initialize hasher with configurable threshold.

        Args:
            full_hash_threshold: File size threshold in bytes for full vs enhanced hashing.
                                Default: 2GB - full hash files smaller than this.
        """
        self.full_hash_threshold = full_hash_threshold
        self.chunk_size = 8 * 1024 * 1024  # 8MB chunks for optimal I/O

    def hash_file(self, file_path: str) -> str:
        """
        Hash a file using the most appropriate strategy based on size.

        Args:
            file_path: Path to file to hash

        Returns:
            Hash string with prefix indicating method used

        Raises:
            OSError: If file cannot be read
            ValueError: If file is empty or invalid
        """
        return self.hash_file_with_stat(file_path, None)

    def hash_file_with_stat(self, file_path: str, file_stat: Optional[os.stat_result]) -> str:
        """
        Hash a file using the most appropriate strategy based on size, with optional stat reuse.

        Args:
            file_path: Path to file to hash
            file_stat: Optional pre-computed os.stat_result to avoid redundant calls

        Returns:
            Hash string with prefix indicating method used

        Raises:
            OSError: If file cannot be read
            ValueError: If file is empty or invalid
        """
        if not os.path.isfile(file_path):
            raise ValueError(f"File does not exist: {file_path}")

        # Get file stat once if not provided
        if file_stat is None:
            file_stat = os.stat(file_path)

        file_size = file_stat.st_size

        if file_size == 0:
            raise ValueError(f"File is empty: {file_path}")

        if file_size <= self.full_hash_threshold:
            return self._secure_full_hash_with_stat(file_path, file_stat)
        else:
            logger.info(f"Large file ({file_size / 1024**3:.1f}GB), using enhanced fingerprint for {file_path}")
            return self._secure_enhanced_fingerprint_with_stat(file_path, file_stat)

    def _secure_full_hash(self, file_path: str) -> str:
        """
        Compute cryptographically secure full file hash using Blake2b.

        Args:
            file_path: Path to file to hash

        Returns:
            Hash string with 'secure:' prefix
        """
        file_stat = os.stat(file_path)
        return self._secure_full_hash_with_stat(file_path, file_stat)

    def _secure_full_hash_with_stat(self, file_path: str, file_stat: os.stat_result) -> str:
        """
        Compute cryptographically secure full file hash using Blake2b with stat reuse.

        Args:
            file_path: Path to file to hash
            file_stat: Pre-computed os.stat_result

        Returns:
            Hash string with 'secure:' prefix
        """
        start_time = time.time()
        hasher = hashlib.blake2b(digest_size=32)  # 256-bit output
        file_size = file_stat.st_size

        try:
            if file_size < 100 * 1024 * 1024:  # < 100MB - use memory mapping
                try:
                    with open(file_path, "rb") as f:
                        pre_mmap_size = os.fstat(f.fileno()).st_size
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            post_mmap_size = os.fstat(f.fileno()).st_size
                            if pre_mmap_size != post_mmap_size or pre_mmap_size != mm.size():
                                raise ValueError(f"File size changed during hashing (TOCTTOU detected) for {file_path}")
                            hasher.update(mm)
                except (OSError, ValueError) as mmap_error:
                    # Fallback to reading in chunks if mmap fails (empty files, unsupported file types)
                    logger.debug(f"mmap failed for {file_path}: {mmap_error}. Falling back to chunked read.")
                    with open(file_path, "rb") as f:
                        while chunk := f.read(self.chunk_size):
                            hasher.update(chunk)
            else:
                # Stream large files in chunks
                with open(file_path, "rb") as f:
                    while chunk := f.read(self.chunk_size):
                        hasher.update(chunk)

        except OSError as e:
            raise OSError(f"Failed to hash file {file_path}: {e}") from e

        hash_time = time.time() - start_time
        hash_hex = hasher.hexdigest()

        logger.debug(f"Full hash of {file_path} ({file_size / 1024**2:.1f}MB) took {hash_time:.2f}s")

        return f"secure:{hash_hex}"

    def _secure_enhanced_fingerprint(self, file_path: str, file_size: int) -> str:
        """
        Compute security-conscious fingerprint for very large files.

        Hashes significant portions distributed throughout the file
        to make tampering detectable while being faster than full hash.

        Args:
            file_path: Path to file to hash
            file_size: Size of file in bytes

        Returns:
            Hash string with 'fingerprint:' prefix
        """
        file_stat = os.stat(file_path)
        return self._secure_enhanced_fingerprint_with_stat(file_path, file_stat)

    def _secure_enhanced_fingerprint_with_stat(self, file_path: str, file_stat: os.stat_result) -> str:
        """
        Compute security-conscious fingerprint for very large files with stat reuse.

        Hashes significant portions distributed throughout the file
        to make tampering detectable while being faster than full hash.

        Args:
            file_path: Path to file to hash
            file_stat: Pre-computed os.stat_result

        Returns:
            Hash string with 'fingerprint:' prefix
        """
        start_time = time.time()
        hasher = hashlib.blake2b(digest_size=32)
        file_size = file_stat.st_size

        # Define portions to hash - strategically distributed
        portions_to_hash = [
            (0, 2 * 1024 * 1024),  # First 2MB
            (file_size // 4, 1 * 1024 * 1024),  # 1MB at 25%
            (file_size // 2, 1 * 1024 * 1024),  # 1MB at 50%
            (3 * file_size // 4, 1 * 1024 * 1024),  # 1MB at 75%
            (max(0, file_size - 2 * 1024 * 1024), 2 * 1024 * 1024),  # Last 2MB
        ]

        try:
            with open(file_path, "rb") as f:
                for offset, length in portions_to_hash:
                    f.seek(offset)
                    data = f.read(length)
                    hasher.update(data)

        except OSError as e:
            raise OSError(f"Failed to hash file {file_path}: {e}") from e

        # Include metadata for additional security - reuse stat
        hasher.update(str(file_size).encode())
        hasher.update(str(int(file_stat.st_mtime)).encode())
        hasher.update(str(file_stat.st_ino).encode())  # inode for uniqueness

        hash_time = time.time() - start_time
        hash_hex = hasher.hexdigest()

        logger.debug(f"Enhanced fingerprint of {file_path} ({file_size / 1024**3:.1f}GB) took {hash_time:.2f}s")

        return f"fingerprint:{hash_hex}"

    def verify_hash(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify that a file matches an expected hash.

        Args:
            file_path: Path to file to verify
            expected_hash: Expected hash string (with prefix)

        Returns:
            True if hash matches, False otherwise
        """
        try:
            current_hash = self.hash_file(file_path)
            return current_hash == expected_hash
        except Exception as e:
            logger.warning(f"Hash verification failed for {file_path}: {e}")
            return False

    def get_hash_info(self, hash_string: str) -> dict:
        """
        Parse hash string and return information about hashing method used.

        Args:
            hash_string: Hash string with prefix

        Returns:
            Dictionary with hash method info
        """
        if hash_string.startswith("secure:"):
            return {
                "method": "full_hash",
                "algorithm": "blake2b",
                "security_level": "high",
                "hash": hash_string[7:],  # Remove 'secure:' prefix
            }
        elif hash_string.startswith("fingerprint:"):
            return {
                "method": "enhanced_fingerprint",
                "algorithm": "blake2b",
                "security_level": "medium",
                "hash": hash_string[12:],  # Remove 'fingerprint:' prefix
            }
        else:
            return {"method": "unknown", "algorithm": "unknown", "security_level": "unknown", "hash": hash_string}


class HashVerificationError(Exception):
    """Raised when hash verification fails."""

    pass


def hash_file_secure(file_path: str, threshold: Optional[int] = None) -> str:
    """
    Convenience function to hash a file securely.

    Args:
        file_path: Path to file to hash
        threshold: Optional threshold for full vs fingerprint hashing

    Returns:
        Secure hash string
    """
    hasher = SecureFileHasher(threshold) if threshold else SecureFileHasher()
    return hasher.hash_file(file_path)


def verify_file_hash(file_path: str, expected_hash: str) -> bool:
    """
    Convenience function to verify a file hash.

    Args:
        file_path: Path to file to verify
        expected_hash: Expected hash string

    Returns:
        True if hash matches, False otherwise
    """
    hasher = SecureFileHasher()
    return hasher.verify_hash(file_path, expected_hash)


# Performance testing function
def benchmark_hashing_performance(test_file_path: str, iterations: int = 3) -> dict:
    """
    Benchmark hashing performance on a test file.

    Args:
        test_file_path: Path to file to test with
        iterations: Number of iterations to average

    Returns:
        Performance statistics
    """
    if not os.path.isfile(test_file_path):
        raise ValueError(f"Test file does not exist: {test_file_path}")

    hasher = SecureFileHasher()
    file_size = os.path.getsize(test_file_path)

    times = []
    for i in range(iterations):
        start_time = time.time()
        hash_result = hasher.hash_file(test_file_path)
        elapsed = time.time() - start_time
        times.append(elapsed)

        if i == 0:
            first_hash = hash_result
        else:
            # Verify consistency
            assert hash_result == first_hash, "Hash inconsistency detected!"

    avg_time = sum(times) / len(times)
    throughput_mbps = (file_size / (1024 * 1024)) / avg_time

    return {
        "file_size_mb": file_size / (1024 * 1024),
        "avg_time_seconds": avg_time,
        "min_time_seconds": min(times),
        "max_time_seconds": max(times),
        "throughput_mbps": throughput_mbps,
        "hash_method": hasher.get_hash_info(first_hash)["method"],
        "hash_result": first_hash,
    }
