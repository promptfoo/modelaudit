"""
Large file handling utilities for ModelAudit.

This module provides utilities for scanning large model files efficiently
with chunked reading, progress reporting, and memory management.
"""

import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..scanners.base import IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

# Size thresholds for different scanning strategies
SMALL_FILE_THRESHOLD = 10 * 1024 * 1024 * 1024  # 10GB - scan normally
MEDIUM_FILE_THRESHOLD = 500 * 1024 * 1024 * 1024  # 500GB - use chunking
LARGE_FILE_THRESHOLD = 1024 * 1024 * 1024 * 1024  # 1TB - use streaming
VERY_LARGE_FILE_THRESHOLD = 2 * 1024 * 1024 * 1024 * 1024  # 2TB - special handling

# Default chunk sizes for different file sizes
DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024 * 1024  # 10GB chunks
LARGE_CHUNK_SIZE = 50 * 1024 * 1024 * 1024  # 50GB chunks for large files
STREAM_BUFFER_SIZE = 1024 * 1024  # 1MB buffer for streaming


class LargeFileHandler:
    """Handler for scanning large model files efficiently."""

    def __init__(
        self,
        file_path: str,
        scanner: Any,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        timeout: int = 3600,
    ):
        """
        Initialize the large file handler.

        Args:
            file_path: Path to the file to scan
            scanner: Scanner instance to use
            progress_callback: Optional callback for progress updates
            timeout: Maximum time allowed for scanning (seconds)
        """
        self.file_path = file_path
        self.scanner = scanner
        self.progress_callback = progress_callback
        self.timeout = timeout
        self.start_time = time.time()

        # Get file size
        self.file_size = os.path.getsize(file_path)
        self.file_name = Path(file_path).name

        # Determine scanning strategy based on file size
        self.strategy = self._determine_strategy()

    def _determine_strategy(self) -> str:
        """Determine the best scanning strategy based on file size."""
        if self.file_size <= SMALL_FILE_THRESHOLD:
            return "normal"
        elif self.file_size <= MEDIUM_FILE_THRESHOLD:
            return "chunked"
        elif self.file_size <= LARGE_FILE_THRESHOLD:
            return "streaming"
        else:
            return "optimized"

    def _check_timeout(self) -> bool:
        """Check if scanning has exceeded timeout."""
        return (time.time() - self.start_time) > self.timeout

    def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress if callback is available."""
        if self.progress_callback:
            self.progress_callback(message, percentage)

    def scan(self) -> ScanResult:
        """
        Scan the file using the appropriate strategy.

        Returns:
            ScanResult with findings
        """
        logger.debug(f"File scan strategy: {self.strategy} for {self.file_name} ({self.file_size:,} bytes)")

        if self.strategy == "normal":
            return self._scan_normal()
        elif self.strategy == "chunked":
            return self._scan_chunked()
        elif self.strategy == "streaming":
            return self._scan_streaming()
        else:  # optimized
            return self._scan_optimized()

    def _scan_normal(self) -> ScanResult:
        """Normal scanning for small files."""
        self._report_progress(f"Scanning {self.file_name}", 0)

        # Use the scanner's normal scan method
        result: ScanResult = self.scanner.scan(self.file_path)

        self._report_progress(f"Completed {self.file_name}", 100)
        return result

    def _scan_chunked(self) -> ScanResult:
        """Chunked scanning for medium files."""
        result = ScanResult(scanner_name=self.scanner.name)
        bytes_processed = 0
        chunk_size = DEFAULT_CHUNK_SIZE
        success = True

        self._report_progress(f"Scanning {self.file_name} in chunks", 0)

        try:
            # For pickle files, we need special handling
            if hasattr(self.scanner, "_scan_pickle_chunks"):
                chunk_result: ScanResult = self.scanner._scan_pickle_chunks(
                    self.file_path, chunk_size, self.progress_callback
                )
                if chunk_result.end_time is None:
                    chunk_result.finish(success=not chunk_result.has_errors)
                return chunk_result

            # For other scanners, fall back to normal scanning
            # but with progress updates
            with open(self.file_path, "rb") as f:
                while True:
                    if self._check_timeout():
                        result.add_issue(
                            f"Scan timeout after {self.timeout} seconds",
                            severity=IssueSeverity.WARNING,
                            details={
                                "bytes_processed": bytes_processed,
                                "total_bytes": self.file_size,
                                "percentage": (bytes_processed / self.file_size) * 100,
                            },
                        )
                        success = False
                        break

                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    bytes_processed += len(chunk)
                    percentage = (bytes_processed / self.file_size) * 100
                    self._report_progress(
                        f"Scanning {self.file_name}: {bytes_processed:,}/{self.file_size:,} bytes", percentage
                    )

                    # Analyze chunk for patterns
                    if hasattr(self.scanner, "_analyze_chunk"):
                        chunk_result = self.scanner._analyze_chunk(chunk, bytes_processed)
                        result.merge(chunk_result)

            # If scanner doesn't support chunking, fall back to normal scan
            if bytes_processed == 0:
                normal_result = self._scan_normal()
                if normal_result.end_time is None:
                    normal_result.finish(success=not normal_result.has_errors)
                return normal_result

        except Exception as e:
            logger.error(f"Error during chunked scanning: {e}")
            result.add_issue(
                f"Scanning error: {e!s}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e)},
            )
            success = False

        result.bytes_scanned = bytes_processed
        self._report_progress(f"Completed {self.file_name}", 100)
        result.finish(success=success and not result.has_errors)
        return result

    def _scan_streaming(self) -> ScanResult:
        """Streaming scan for large files - always scans completely for security."""
        # Security requires complete file scanning
        return self._scan_normal()

    def _scan_optimized(self) -> ScanResult:
        """Optimized scanning for large files (>8GB) - still scans completely."""
        # Security requires complete file scanning
        return self._scan_normal()


def should_use_large_file_handler(file_path: str) -> bool:
    """
    Determine if a file should use the large file handler.

    Args:
        file_path: Path to the file

    Returns:
        True if the file exceeds approximately 10GB
        and should use the large file handler
    """
    try:
        file_size = os.path.getsize(file_path)
        return file_size > SMALL_FILE_THRESHOLD
    except OSError:
        return False


def scan_large_file(
    file_path: str,
    scanner: Any,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    timeout: int = 3600,
) -> ScanResult:
    """
    Scan a large file with appropriate strategy.

    Args:
        file_path: Path to the file to scan
        scanner: Scanner instance to use
        progress_callback: Optional progress callback
        timeout: Maximum scan time in seconds

    Returns:
        ScanResult with findings
    """
    # Check if caching is enabled in scanner config
    config = getattr(scanner, "config", {})
    cache_enabled = config.get("cache_enabled", True)
    cache_dir = config.get("cache_dir")

    # If caching is disabled, proceed with direct scan
    if not cache_enabled:
        return _scan_large_file_internal(file_path, scanner, progress_callback, timeout)

    # Use cache manager for large file scans
    try:
        from ..cache import get_cache_manager

        cache_manager = get_cache_manager(cache_dir, enabled=True)

        # Create wrapper function for cache manager
        def cached_large_scan_wrapper(fpath: str) -> dict:
            result = _scan_large_file_internal(fpath, scanner, progress_callback, timeout)
            return result.to_dict()

        # Get cached result or perform scan
        result_dict = cache_manager.cached_scan(file_path, cached_large_scan_wrapper)

        # Convert back to ScanResult
        from .result_conversion import scan_result_from_dict

        return scan_result_from_dict(result_dict)

    except Exception as e:
        # If cache system fails, fall back to direct scanning
        logger.warning(f"Large file cache error for {file_path}: {e}. Falling back to direct scan.")
        return _scan_large_file_internal(file_path, scanner, progress_callback, timeout)


def _scan_large_file_internal(
    file_path: str,
    scanner: Any,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    timeout: int = 3600,
) -> ScanResult:
    """
    Internal implementation of large file scanning (cache-agnostic).

    Args:
        file_path: Path to the file to scan
        scanner: Scanner instance to use
        progress_callback: Optional progress callback
        timeout: Maximum scan time in seconds

    Returns:
        ScanResult with findings
    """
    handler = LargeFileHandler(
        file_path=file_path, scanner=scanner, progress_callback=progress_callback, timeout=timeout
    )
    return handler.scan()
