"""
Advanced file handling utilities for ModelAudit.

This module provides advanced utilities for scanning large model files (400B+ parameters)
with memory-mapped I/O, sharded model support, and distributed scanning capabilities.
"""

import logging
import mmap
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, ClassVar, Optional

from ..scanners.base import IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

# Size thresholds for large models
EXTREME_MODEL_THRESHOLD = 50 * 1024 * 1024 * 1024  # 50GB - use memory mapping
LARGE_MODEL_THRESHOLD_200GB = 500 * 1024 * 1024 * 1024  # 500GB - distributed scanning
COLOSSAL_MODEL_THRESHOLD = 1024 * 1024 * 1024 * 1024  # 1TB - special handling

# Memory mapping parameters
MMAP_CHUNK_SIZE = 100 * 1024 * 1024  # 100MB chunks for memory mapping
MMAP_MAX_WINDOW = 500 * 1024 * 1024  # 500MB max window size

# Parallel scanning parameters
MAX_PARALLEL_WORKERS = 4
SHARD_SCAN_TIMEOUT = 600  # 10 minutes per shard


class ShardedModelDetector:
    """Detect and handle sharded model files."""

    # Common sharding patterns for large models
    SHARD_PATTERNS: ClassVar[list[str]] = [
        r"pytorch_model-(\d+)-of-(\d+)\.bin",  # HuggingFace PyTorch sharding
        r"model-(\d+)-of-(\d+)\.safetensors",  # SafeTensors sharding
        r"model\.ckpt-(\d+)\.data-\d+-of-\d+",  # TensorFlow sharding
        r"model_weights_(\d+)\.h5",  # Keras sharding
        r"checkpoint_(\d+)\.pt",  # PyTorch checkpoint sharding
        r"params_shard_(\d+)\.bin",  # Custom parameter sharding
    ]

    @classmethod
    def detect_shards(cls, file_path: str) -> Optional[dict[str, Any]]:
        """
        Detect if a file is part of a sharded model.

        Args:
            file_path: Path to check

        Returns:
            Dictionary with shard info if detected, None otherwise
        """
        file_name = Path(file_path).name
        dir_path = Path(file_path).parent

        for pattern in cls.SHARD_PATTERNS:
            match = re.match(pattern, file_name)
            if match:
                # Found a sharded model
                shard_info: dict[str, Any] = {"pattern": pattern, "current_file": file_path, "shards": []}

                # Find all related shards
                for file in dir_path.glob("*"):
                    if re.match(pattern, file.name):
                        shard_info["shards"].append(str(file))

                shard_info["shards"].sort()
                shard_info["total_shards"] = len(shard_info["shards"])

                # Calculate total size
                total_size = sum(os.path.getsize(s) for s in shard_info["shards"])
                shard_info["total_size"] = total_size

                return shard_info

        return None

    @classmethod
    def find_model_config(cls, file_path: str) -> Optional[str]:
        """Find the configuration file for a sharded model."""
        dir_path = Path(file_path).parent

        # Common config file names
        config_names = [
            "config.json",
            "model.safetensors.index.json",
            "pytorch_model.bin.index.json",
            "tf_model.h5.index.json",
            "model_index.json",
        ]

        for config_name in config_names:
            config_path = dir_path / config_name
            if config_path.exists():
                return str(config_path)

        return None


class MemoryMappedScanner:
    """Scanner using memory-mapped I/O for large file sizes."""

    def __init__(self, file_path: str, scanner: Any):
        """
        Initialize memory-mapped scanner.

        Args:
            file_path: Path to the file
            scanner: Scanner instance to use
        """
        self.file_path = file_path
        self.scanner = scanner
        self.file_size = os.path.getsize(file_path)

    def scan_with_mmap(self, progress_callback: Optional[Callable[[str, float], None]] = None) -> ScanResult:
        """
        Scan file using memory mapping.

        Args:
            progress_callback: Optional progress callback

        Returns:
            ScanResult with findings
        """
        result = ScanResult(scanner_name=self.scanner.name)
        bytes_scanned = 0

        try:
            with open(self.file_path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                # Scan in windows to avoid loading entire file
                window_size = min(MMAP_MAX_WINDOW, self.file_size)
                position = 0

                while position < self.file_size:
                    # Calculate window boundaries
                    end_pos = min(position + window_size, self.file_size)

                    # Extract window data
                    window_data = mmapped_file[position:end_pos]

                    # Analyze window for suspicious patterns
                    window_result = self._analyze_window(window_data, position)
                    result.merge(window_result)

                    bytes_scanned += len(window_data)

                    # Progress reporting
                    if progress_callback:
                        percentage = (bytes_scanned / self.file_size) * 100
                        progress_callback(f"Memory-mapped scan: {bytes_scanned:,}/{self.file_size:,} bytes", percentage)

                    # Move to next window with small overlap
                    if end_pos >= self.file_size:
                        break  # Reached end of file
                    position = end_pos - (1024 * 1024)  # 1MB overlap
                    if position <= 0:
                        position = end_pos  # Avoid going negative

                result.bytes_scanned = bytes_scanned

        except Exception as e:
            logger.error(f"Error during memory-mapped scanning: {e}")
            result.add_issue(
                f"Memory-mapped scan error: {e!s}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e), "bytes_scanned": bytes_scanned},
            )

        return result

    def _analyze_window(self, data: bytes, offset: int) -> ScanResult:
        """Analyze a window of data using the actual scanner's checks."""
        result = ScanResult(scanner_name=self.scanner.name)

        # First, run scanner-specific analysis if available
        if hasattr(self.scanner, "_analyze_chunk"):
            # Scanner has chunk analysis capability
            chunk_result = self.scanner._analyze_chunk(data, offset)
            result.merge(chunk_result)
        elif hasattr(self.scanner, "_analyze_bytes"):
            # Scanner can analyze raw bytes
            bytes_result = self.scanner._analyze_bytes(data, offset)
            result.merge(bytes_result)
        else:
            # Fall back to pattern matching for all scanners
            # This ensures we still catch obvious malicious patterns
            suspicious_patterns = [
                (b"exec", "exec() call detected"),
                (b"eval", "eval() call detected"),
                (b"__import__", "Dynamic import detected"),
                (b"os.system", "System command execution detected"),
                (b"subprocess", "Subprocess execution detected"),
                (b"pickle.loads", "Pickle deserialization detected"),
                (b"marshal.loads", "Marshal deserialization detected"),
                (b"compile(", "compile() call detected"),
                (b"__builtins__", "Builtins access detected"),
                (b"getattr", "Dynamic attribute access detected"),
            ]

            for pattern, message in suspicious_patterns:
                if pattern in data:
                    result.add_issue(
                        message,
                        severity=IssueSeverity.CRITICAL,
                        location=f"offset {offset:,}",
                        details={"pattern": pattern.decode("utf-8", errors="ignore"), "offset": offset},
                    )

        # Run any additional scanner-specific checks
        if hasattr(self.scanner, "check_for_embedded_secrets"):
            # Check for embedded secrets in this window
            self.scanner.check_for_embedded_secrets(data, result, f"offset {offset:,}")

        if hasattr(self.scanner, "check_for_dangerous_imports"):
            # Check for dangerous imports
            self.scanner.check_for_dangerous_imports(data, result, f"offset {offset:,}")

        return result


class ParallelShardScanner:
    """Scan multiple model shards in parallel."""

    def __init__(self, shard_info: dict[str, Any], scanner_class: type):
        """
        Initialize parallel shard scanner.

        Args:
            shard_info: Information about model shards
            scanner_class: Scanner class to use
        """
        self.shard_info = shard_info
        self.scanner_class = scanner_class

    def scan_shards(self, progress_callback: Optional[Callable[[str, float], None]] = None) -> ScanResult:
        """
        Scan all shards in parallel.

        Args:
            progress_callback: Optional progress callback

        Returns:
            Combined ScanResult from all shards
        """
        result = ScanResult(scanner_name="parallel_shard_scanner")
        shards = self.shard_info["shards"]
        total_shards = len(shards)
        completed_shards = 0

        # Add info about sharded model
        result.add_issue(
            f"Scanning sharded model with {total_shards} parts",
            severity=IssueSeverity.INFO,
            details={
                "total_shards": total_shards,
                "total_size": self.shard_info["total_size"],
                "shards": shards,
            },
        )

        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_WORKERS, total_shards)) as executor:
            # Submit all shard scans
            future_to_shard = {executor.submit(self._scan_single_shard, shard): shard for shard in shards}

            # Process results as they complete
            for future in as_completed(future_to_shard):
                shard = future_to_shard[future]
                completed_shards += 1

                try:
                    shard_result = future.result(timeout=SHARD_SCAN_TIMEOUT)
                    result.merge(shard_result)

                    if progress_callback:
                        percentage = (completed_shards / total_shards) * 100
                        progress_callback(f"Scanned shard {completed_shards}/{total_shards}", percentage)

                except Exception as e:
                    logger.error(f"Error scanning shard {shard}: {e}")
                    result.add_issue(
                        f"Error scanning shard: {Path(shard).name}",
                        severity=IssueSeverity.WARNING,
                        location=shard,
                        details={"error": str(e)},
                    )

        return result

    def _scan_single_shard(self, shard_path: str) -> ScanResult:
        """Scan a single shard file."""
        scanner = self.scanner_class()
        result: ScanResult = scanner.scan(shard_path)
        return result


class AdvancedFileHandler:
    """Handler for large model files (400B+ parameters)."""

    def __init__(
        self,
        file_path: str,
        scanner: Any,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        timeout: int = 7200,  # 2 hours for large models
    ):
        """
        Initialize advanced file handler.

        Args:
            file_path: Path to the file
            scanner: Scanner instance
            progress_callback: Optional progress callback
            timeout: Maximum scan time
        """
        self.file_path = file_path
        self.scanner = scanner
        self.progress_callback = progress_callback
        self.timeout = timeout
        self.start_time = time.time()

        # Check for sharded model
        self.shard_info = ShardedModelDetector.detect_shards(file_path)

        # Get file/model size
        if self.shard_info:
            self.total_size = self.shard_info["total_size"]
            self.is_sharded = True
        else:
            self.total_size = os.path.getsize(file_path)
            self.is_sharded = False

    def scan(self) -> ScanResult:
        """
        Scan the large model file.

        Returns:
            ScanResult with findings
        """
        logger.debug(f"Advanced scan initialized: {self.total_size:,} bytes, sharded={self.is_sharded}")

        # Determine scanning strategy
        if self.is_sharded:
            return self._scan_sharded_model()
        elif self.total_size > LARGE_MODEL_THRESHOLD_200GB:
            return self._scan_large_file_distributed()
        elif self.total_size > EXTREME_MODEL_THRESHOLD:
            return self._scan_with_mmap()
        else:
            # Fall back to regular large file handler
            from .large_file_handler import LargeFileHandler

            handler = LargeFileHandler(self.file_path, self.scanner, self.progress_callback, self.timeout)
            return handler.scan()

    def _scan_sharded_model(self) -> ScanResult:
        """Scan a sharded model."""
        result = ScanResult(scanner_name=self.scanner.name)

        # Find and scan config file first
        config_path = ShardedModelDetector.find_model_config(self.file_path)
        if config_path:
            logger.debug(f"Model configuration detected: {config_path}")
            # Quick scan of config for metadata
            try:
                with open(config_path) as f:
                    config_content = f.read(10240)  # Read first 10KB
                    if "torch_dtype" in config_content:
                        result.add_issue(
                            "PyTorch model configuration detected",
                            severity=IssueSeverity.INFO,
                            location=config_path,
                            details={"config_file": config_path},
                        )
            except Exception as e:
                logger.warning(f"Failed to read config file: {e}")

        # Scan shards in parallel
        if self.shard_info:
            parallel_scanner = ParallelShardScanner(self.shard_info, self.scanner.__class__)
            shard_results = parallel_scanner.scan_shards(self.progress_callback)
            result.merge(shard_results)

        return result

    def _scan_with_mmap(self) -> ScanResult:
        """Scan using memory mapping."""
        mmap_scanner = MemoryMappedScanner(self.file_path, self.scanner)
        return mmap_scanner.scan_with_mmap(self.progress_callback)

    def _scan_large_file_distributed(self) -> ScanResult:
        """Scan large files using memory-mapped approach with FULL security checks."""
        logger.info(f"Scanning file ({self.total_size:,} bytes) with full security checks")

        # Add informational note about file size
        result = ScanResult(scanner_name=self.scanner.name)
        result.add_issue(
            f"Scanning file ({self.total_size:,} bytes) - processing may take additional time",
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": "memory-mapped with full checks",
                "note": "All security checks will be performed",
            },
        )

        # Use memory-mapped scanner to run ALL checks
        # This ensures we don't skip any security validations
        mmap_scanner = MemoryMappedScanner(self.file_path, self.scanner)

        # If the scanner has its own scanning method, try to use it with memory mapping
        if hasattr(self.scanner, "_scan_with_mmap"):
            # Scanner supports memory-mapped scanning directly
            scan_result = self.scanner._scan_with_mmap(self.file_path, self.progress_callback)
        else:
            # Use our generic memory-mapped approach but with the scanner's checks
            scan_result = mmap_scanner.scan_with_mmap(self.progress_callback)

            # Also run the scanner's normal checks on sampled sections
            # to ensure we don't miss scanner-specific validations
            try:
                # Let the scanner analyze the header (first 10GB)
                with open(self.file_path, "rb") as f:
                    header_data = f.read(min(10 * 1024 * 1024 * 1024, self.total_size))

                    # If scanner has special header analysis, use it
                    if hasattr(self.scanner, "_analyze_header"):
                        header_result = self.scanner._analyze_header(header_data)
                        scan_result.merge(header_result)
                    elif hasattr(self.scanner, "_analyze_chunk"):
                        header_result = self.scanner._analyze_chunk(header_data, 0)
                        scan_result.merge(header_result)

                    # For scanners that need the full scan method, create a temp file with sample
                    # This ensures pickle scanners, etc. can run their full validation
                    if hasattr(self.scanner, "scan") and not hasattr(self.scanner, "_analyze_chunk"):
                        import tempfile

                        with tempfile.NamedTemporaryFile(suffix=".tmp", delete=False) as tmp:
                            tmp.write(header_data)
                            tmp_path = tmp.name

                        try:
                            # Run scanner's full validation on the sample
                            sample_result = self.scanner.scan(tmp_path)
                            # Merge findings but note they're from a sample
                            for issue in sample_result.issues:
                                issue.message = f"[Sample] {issue.message}"
                            scan_result.merge(sample_result)
                        finally:
                            import os as os_module

                            os_module.unlink(tmp_path)

            except Exception as e:
                logger.warning(f"Error running additional scanner checks: {e}")

        result.merge(scan_result)
        return result


def should_use_advanced_handler(file_path: str) -> bool:
    """
    Check if file should use advanced file handler.

    Args:
        file_path: Path to check

    Returns:
        True if advanced handler should be used
    """
    # Check for sharded model
    if ShardedModelDetector.detect_shards(file_path):
        return True

    # Check file size
    try:
        file_size = os.path.getsize(file_path)
        return file_size > EXTREME_MODEL_THRESHOLD
    except OSError:
        return False


def scan_advanced_large_file(
    file_path: str,
    scanner: Any,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    timeout: int = 7200,
) -> ScanResult:
    """
    Scan a large file with advanced handler.

    Args:
        file_path: Path to scan
        scanner: Scanner instance
        progress_callback: Progress callback
        timeout: Maximum scan time

    Returns:
        ScanResult with findings
    """
    # Check if caching is enabled in scanner config
    config = getattr(scanner, "config", {})
    cache_enabled = config.get("cache_enabled", True)
    cache_dir = config.get("cache_dir")

    # If caching is disabled, proceed with direct scan
    if not cache_enabled:
        return _scan_advanced_large_file_internal(file_path, scanner, progress_callback, timeout)

    # Use cache manager for advanced large file scans
    try:
        from ..cache import get_cache_manager

        cache_manager = get_cache_manager(cache_dir, enabled=True)

        # Create wrapper function for cache manager
        def cached_advanced_scan_wrapper(fpath: str) -> dict:
            result = _scan_advanced_large_file_internal(fpath, scanner, progress_callback, timeout)
            return result.to_dict()

        # Get cached result or perform scan
        result_dict = cache_manager.cached_scan(file_path, cached_advanced_scan_wrapper)

        # Convert back to ScanResult
        from .result_conversion import scan_result_from_dict

        return scan_result_from_dict(result_dict)

    except Exception as e:
        # If cache system fails, fall back to direct scanning
        logger.warning(f"Advanced file cache error for {file_path}: {e}. Falling back to direct scan.")
        return _scan_advanced_large_file_internal(file_path, scanner, progress_callback, timeout)


def _scan_advanced_large_file_internal(
    file_path: str,
    scanner: Any,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    timeout: int = 7200,
) -> ScanResult:
    """
    Internal implementation of advanced large file scanning (cache-agnostic).

    Args:
        file_path: Path to scan
        scanner: Scanner instance
        progress_callback: Progress callback
        timeout: Maximum scan time

    Returns:
        ScanResult with findings
    """
    handler = AdvancedFileHandler(file_path, scanner, progress_callback, timeout)
    return handler.scan()
