"""
Advanced file handling utilities for ModelAudit.

This module provides advanced utilities for scanning large model files (400B+ parameters)
with memory-mapped I/O, sharded model support, and distributed scanning capabilities.
"""

import logging
import mmap
import os
import re
import stat
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from contextvars import copy_context
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ..helpers.cache_decorator import should_bypass_cache_for_safetensors_header_limit

if TYPE_CHECKING:
    from ...scanner_results import ScanResult

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
MAX_RECORDED_MISSING_SHARD_INDICES = 1000


def _is_resolved_path_within_directory(base_dir: Path, resolved_target: str) -> bool:
    """Return True when a resolved target remains inside the shard directory."""
    try:
        base_path = base_dir.resolve()
        target_path = Path(resolved_target).resolve()
    except (OSError, RuntimeError):
        return False
    if os.name == "nt":
        base_norm = os.path.normcase(os.path.normpath(str(base_path)))
        target_norm = os.path.normcase(os.path.normpath(str(target_path)))
        try:
            return os.path.commonpath([target_norm, base_norm]) == base_norm
        except ValueError:
            return False
    return target_path.is_relative_to(base_path)


def _mark_inconclusive_scan_outcome(result: "ScanResult", reason: str) -> None:
    """Mark a scan result as incomplete while preserving existing reasons."""
    from ...scanner_results import INCONCLUSIVE_SCAN_OUTCOME

    result.metadata["analysis_incomplete"] = True
    result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
    existing_reasons = result.metadata.get("scan_outcome_reasons")
    reasons = existing_reasons if isinstance(existing_reasons, list) else []
    if reason not in reasons:
        reasons.append(reason)
    result.metadata["scan_outcome_reasons"] = reasons


def _summarize_missing_shard_indices(
    present_indices: set[int],
    expected_total: int,
) -> tuple[list[int], int, bool]:
    """Return a bounded sample, total count, and truncation flag for missing shards."""
    bounded_present_indices = {index for index in present_indices if 1 <= index <= expected_total}
    missing_count = max(expected_total - len(bounded_present_indices), 0)
    if missing_count == 0:
        return [], 0, False

    missing_indices: list[int] = []
    next_candidate = 1
    for present_index in sorted(bounded_present_indices):
        while next_candidate < present_index and len(missing_indices) < MAX_RECORDED_MISSING_SHARD_INDICES:
            missing_indices.append(next_candidate)
            next_candidate += 1
        if len(missing_indices) >= MAX_RECORDED_MISSING_SHARD_INDICES:
            break
        next_candidate = present_index + 1

    while next_candidate <= expected_total and len(missing_indices) < MAX_RECORDED_MISSING_SHARD_INDICES:
        missing_indices.append(next_candidate)
        next_candidate += 1

    return missing_indices, missing_count, missing_count > len(missing_indices)


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
    def match_shard_filename(cls, file_name: str) -> dict[str, int | str | None] | None:
        """Return shard metadata for a filename when it matches a known shard pattern."""
        for pattern in cls.SHARD_PATTERNS:
            match = re.fullmatch(pattern, file_name)
            if not match:
                continue

            current_shard_index: int | None = None
            expected_total_shards: int | None = None
            if match.lastindex:
                with suppress(IndexError, ValueError):
                    current_shard_index = int(match.group(1))
            if (match.lastindex or 0) >= 2:
                with suppress(IndexError, ValueError):
                    expected_total_shards = int(match.group(2))

            return {
                "pattern": pattern,
                "current_shard_index": current_shard_index,
                "expected_total_shards": expected_total_shards,
            }

        return None

    @classmethod
    def detect_shards(
        cls,
        file_path: str,
        *,
        allowed_paths: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Detect if a file is part of a sharded model.

        Args:
            file_path: Path to check

        Returns:
            Dictionary with shard info if detected, None otherwise
        """
        file_name = Path(file_path).name
        dir_path = Path(file_path).parent
        requested_path = str(Path(file_path).absolute())
        allowed_path_set: set[str] | None = None
        if allowed_paths is not None:
            allowed_path_set = {os.path.normcase(os.path.normpath(os.path.abspath(path))) for path in allowed_paths}

        for pattern in cls.SHARD_PATTERNS:
            match = re.fullmatch(pattern, file_name)
            if match:
                # Found a sharded model
                shard_info: dict[str, Any] = {"pattern": pattern, "current_file": file_path, "shards": []}
                expected_totals: set[int] = set()
                present_indices: set[int] = set()
                unreadable_shards: list[str] = []
                out_of_scope_shards: list[str] = []
                unvalidated_shards: list[str] = []
                shard_targets: dict[str, dict[str, int | str]] = {}
                total_size = 0
                requested_expected_total: int | None = None
                if (match.lastindex or 0) >= 2:
                    with suppress(IndexError, ValueError):
                        requested_expected_total = int(match.group(2))
                        expected_totals.add(requested_expected_total)

                # Find all related shards
                for file in dir_path.glob("*"):
                    file_match = re.fullmatch(pattern, file.name)
                    if file_match:
                        candidate_expected_total: int | None = None
                        if (file_match.lastindex or 0) >= 2:
                            with suppress(IndexError, ValueError):
                                candidate_expected_total = int(file_match.group(2))
                        if (
                            requested_expected_total is not None
                            and candidate_expected_total != requested_expected_total
                        ):
                            continue
                        try:
                            resolved_file = str(file.resolve(strict=True))
                        except (OSError, RuntimeError):
                            unreadable_shards.append(str(file))
                            continue
                        normalized_resolved_file = os.path.normcase(os.path.normpath(resolved_file))
                        if allowed_path_set is not None and normalized_resolved_file not in allowed_path_set:
                            if not _is_resolved_path_within_directory(dir_path, resolved_file):
                                out_of_scope_shards.append(str(file))
                            else:
                                unvalidated_shards.append(str(file))
                            continue
                        if (
                            allowed_path_set is None
                            and not _is_resolved_path_within_directory(
                                dir_path,
                                resolved_file,
                            )
                            and str(file.absolute()) != requested_path
                        ):
                            out_of_scope_shards.append(str(file))
                            continue
                        try:
                            shard_stat = os.stat(resolved_file, follow_symlinks=False)
                        except OSError:
                            unreadable_shards.append(str(file))
                            continue
                        if not stat.S_ISREG(shard_stat.st_mode):
                            unreadable_shards.append(str(file))
                            continue
                        shard_size = shard_stat.st_size
                        shard_info["shards"].append(str(file))
                        shard_targets[str(file)] = {
                            "resolved_path": resolved_file,
                            "device": shard_stat.st_dev,
                            "inode": shard_stat.st_ino,
                            "size": shard_size,
                        }
                        total_size += shard_size
                        if file_match.lastindex:
                            with suppress(IndexError, ValueError):
                                present_indices.add(int(file_match.group(1)))

                if not shard_info["shards"]:
                    return None

                shard_info["shards"].sort()
                shard_info["shard_targets"] = shard_targets
                shard_info["total_shards"] = len(shard_info["shards"])
                if unreadable_shards:
                    shard_info["unreadable_shards"] = sorted(unreadable_shards)
                    shard_info["unreadable_shard_count"] = len(unreadable_shards)
                if out_of_scope_shards:
                    shard_info["out_of_scope_shards"] = sorted(out_of_scope_shards)
                    shard_info["out_of_scope_shard_count"] = len(out_of_scope_shards)
                if unvalidated_shards:
                    shard_info["unvalidated_shards"] = sorted(unvalidated_shards)
                    shard_info["unvalidated_shard_count"] = len(unvalidated_shards)
                if expected_totals:
                    expected_total = max(expected_totals)
                    shard_info["expected_total_shards"] = expected_total
                    if present_indices:
                        missing_indices, missing_count, missing_indices_truncated = _summarize_missing_shard_indices(
                            present_indices,
                            expected_total,
                        )
                        if missing_count:
                            shard_info["missing_shard_count"] = missing_count
                            shard_info["missing_shard_indices"] = missing_indices
                            shard_info["missing_shard_indices_truncated"] = missing_indices_truncated

                shard_info["total_size"] = total_size

                return shard_info

        return None

    @classmethod
    def find_model_config(cls, file_path: str) -> str | None:
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
            try:
                resolved_config = config_path.resolve(strict=True)
                config_stat = os.stat(resolved_config, follow_symlinks=False)
            except (OSError, RuntimeError):
                continue
            if not _is_resolved_path_within_directory(dir_path, str(resolved_config)):
                continue
            if stat.S_ISREG(config_stat.st_mode):
                return str(resolved_config)

        return None


def _grouped_shard_boundary_error(file_path: str, allowed_paths: list[str] | None) -> dict[str, str] | None:
    """Return details when a selected shard no longer matches its validated target set."""
    if allowed_paths is None or ShardedModelDetector.match_shard_filename(Path(file_path).name) is None:
        return None
    allowed_path_set = {
        os.path.normcase(os.path.normpath(os.path.abspath(allowed_path))) for allowed_path in allowed_paths
    }
    try:
        resolved_path = Path(file_path).resolve(strict=True)
        resolved_stat = os.stat(resolved_path, follow_symlinks=False)
    except (OSError, RuntimeError) as e:
        return {"path": file_path, "error": str(e), "reason": "shard_target_unavailable"}
    if os.path.normcase(os.path.normpath(str(resolved_path))) not in allowed_path_set:
        return {
            "path": file_path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_outside_validated_family",
        }
    if not stat.S_ISREG(resolved_stat.st_mode):
        return {
            "path": file_path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_not_regular_file",
        }
    return None


def _shard_boundary_failure_result(scanner_name: str, file_path: str, details: dict[str, str]) -> "ScanResult":
    """Build a fail-closed result for a changed grouped shard representative."""
    from ...scanner_results import IssueSeverity, ScanResult

    result = ScanResult(scanner_name=scanner_name)
    result.add_check(
        name="Sharded Model Boundary Check",
        passed=False,
        message="Validated shard path changed before scanning; scan coverage is incomplete.",
        severity=IssueSeverity.INFO,
        location=file_path,
        details={
            **details,
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "shard_boundary_changed",
        },
    )
    result.metadata["operational_error"] = True
    result.metadata["operational_error_reason"] = "shard_boundary_changed"
    _mark_inconclusive_scan_outcome(result, "shard_boundary_changed")
    result.finish(success=False)
    return result


class MemoryMappedHandler:
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

    def scan_with_mmap(self, progress_callback: Callable[[str, float], None] | None = None) -> "ScanResult":
        """
        Scan file using memory mapping.

        Args:
            progress_callback: Optional progress callback

        Returns:
            ScanResult with findings
        """
        from ...scanner_results import IssueSeverity, ScanResult

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
            result.add_check(
                name="Memory-Mapped Scan",
                passed=False,
                message=f"Memory-mapped scan error: {e!s}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e), "bytes_scanned": bytes_scanned},
            )

        result.finish(
            success=not any(
                check.name == "Memory-Mapped Scan" and check.status.value == "failed" for check in result.checks
            )
        )
        return result

    def _analyze_window(self, data: bytes, offset: int) -> "ScanResult":
        """Analyze a window of data using the actual scanner's checks."""
        from ...scanner_results import IssueSeverity, ScanResult

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
                    result.add_check(
                        name="Suspicious Pattern Detection",
                        passed=False,
                        message=message,
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


class ParallelShardHandler:
    """Scan multiple model shards in parallel."""

    def __init__(
        self,
        shard_info: dict[str, Any],
        scanner_class: type,
        scanner_config: dict[str, Any] | None = None,
    ):
        """
        Initialize parallel shard scanner.

        Args:
            shard_info: Information about model shards
            scanner_class: Scanner class to use
            scanner_config: Configuration to preserve for each shard scanner
        """
        self.shard_info = shard_info
        self.scanner_class = scanner_class
        self.scanner_config = scanner_config

    def scan_shards(self, progress_callback: Callable[[str, float], None] | None = None) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

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
        success = True

        # Add info about sharded model
        result.add_check(
            name="Sharded Model Detection",
            passed=True,
            message=f"Scanning sharded model with {total_shards} parts",
            severity=IssueSeverity.INFO,
            details={
                "total_shards": total_shards,
                "total_size": self.shard_info["total_size"],
                "shards": shards,
            },
        )

        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_WORKERS, total_shards)) as executor:
            # Submit all shard scans
            future_to_shard = {
                executor.submit(copy_context().run, self._scan_single_shard, shard): shard for shard in shards
            }

            # Process results as they complete
            for future in as_completed(future_to_shard):
                shard = future_to_shard[future]
                completed_shards += 1

                try:
                    shard_result = future.result(timeout=SHARD_SCAN_TIMEOUT)
                    result.merge(shard_result)
                    success = success and bool(shard_result.success)

                    if progress_callback:
                        percentage = (completed_shards / total_shards) * 100
                        progress_callback(f"Scanned shard {completed_shards}/{total_shards}", percentage)

                except Exception as e:
                    logger.error(f"Error scanning shard {shard}: {e}")
                    success = False
                    _mark_inconclusive_scan_outcome(result, "shard_scan_error")
                    result.add_check(
                        name="Shard Scan",
                        passed=False,
                        message=f"Error scanning shard: {Path(shard).name}",
                        severity=IssueSeverity.INFO,
                        location=shard,
                        details={
                            "error": str(e),
                            "analysis_incomplete": True,
                            "scan_outcome": "inconclusive",
                            "scan_outcome_reason": "shard_scan_error",
                        },
                    )

        result.finish(success=success and not result.has_errors and "scan_outcome" not in result.metadata)
        return result

    def _scan_single_shard(self, shard_path: str) -> "ScanResult":
        from ...scanner_results import ScanResult

        """Scan a single shard file."""
        scanner = (
            self.scanner_class(config=dict(self.scanner_config))
            if self.scanner_config is not None
            else self.scanner_class()
        )
        scan_path = shard_path
        shard_targets = self.shard_info.get("shard_targets")
        if isinstance(shard_targets, dict):
            target = shard_targets.get(shard_path)
            if isinstance(target, dict):
                resolved_path = target.get("resolved_path")
                expected_device = target.get("device")
                expected_inode = target.get("inode")
                if not isinstance(resolved_path, str):
                    raise OSError(f"Missing validated target for shard {Path(shard_path).name}")
                try:
                    current_resolved = str(Path(shard_path).resolve(strict=True))
                    current_stat = os.stat(resolved_path, follow_symlinks=False)
                except (OSError, RuntimeError) as e:
                    raise OSError(f"Validated shard target is no longer available: {Path(shard_path).name}") from e
                if current_resolved != resolved_path or not stat.S_ISREG(current_stat.st_mode):
                    raise OSError(f"Validated shard target changed before scanning: {Path(shard_path).name}")
                if (
                    isinstance(expected_device, int)
                    and isinstance(expected_inode, int)
                    and expected_inode
                    and (current_stat.st_dev, current_stat.st_ino) != (expected_device, expected_inode)
                ):
                    raise OSError(f"Validated shard identity changed before scanning: {Path(shard_path).name}")
                scan_path = resolved_path

        result: ScanResult = scanner.scan(scan_path)
        return result


class AdvancedFileHandler:
    """Handler for large model files (400B+ parameters)."""

    def __init__(
        self,
        file_path: str,
        scanner: Any,
        progress_callback: Callable[[str, float], None] | None = None,
        timeout: int = 7200,  # 2 hours for large models
        allowed_shard_paths: list[str] | None = None,
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
        self.shard_boundary_error = _grouped_shard_boundary_error(file_path, allowed_shard_paths)

        # Check for sharded model
        self.shard_info = (
            None
            if self.shard_boundary_error is not None
            else ShardedModelDetector.detect_shards(file_path, allowed_paths=allowed_shard_paths)
        )

        # Get file/model size
        if self.shard_boundary_error is not None:
            self.total_size = 0
            self.is_sharded = True
        elif self.shard_info:
            self.total_size = self.shard_info["total_size"]
            self.is_sharded = True
        else:
            self.total_size = os.path.getsize(file_path)
            self.is_sharded = False

    def scan(self) -> "ScanResult":
        """
        Scan the large model file.

        Returns:
            ScanResult with findings
        """
        logger.debug(f"Advanced scan initialized: {self.total_size:,} bytes, sharded={self.is_sharded}")

        # Determine scanning strategy
        if self.shard_boundary_error is not None:
            return _shard_boundary_failure_result(self.scanner.name, self.file_path, self.shard_boundary_error)
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

    def _supports_bounded_large_file_analysis(self) -> bool:
        """Return True when the scanner exposes a bounded large-file strategy."""
        return any(hasattr(self.scanner, attr) for attr in ("_scan_with_mmap", "_analyze_chunk", "_analyze_bytes"))

    def _fail_closed_large_file_coverage(self, *, threshold_bytes: int) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Abort with an operational-style result when large-file coverage would be partial."""
        result = ScanResult(scanner_name=self.scanner.name)
        result.add_check(
            name="Large File Detection",
            passed=True,
            message=f"Scanning file ({self.total_size:,} bytes) - processing may take additional time",
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": "unsupported",
                "note": "Bounded analysis unavailable for this scanner; aborting to avoid partial coverage.",
            },
        )
        result.add_check(
            name="Large File Coverage Check",
            passed=False,
            message=(
                "Error scanning file: "
                f"scanner {self.scanner.name} does not support bounded large-file analysis "
                "for this file size; aborting to avoid partial coverage."
            ),
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": "unsupported",
                "scanner": self.scanner.name,
                "threshold_bytes": threshold_bytes,
            },
        )
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = "unsupported_bounded_large_file_analysis"
        result.finish(success=False)
        return result

    def _scan_sharded_model(self) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Scan a sharded model."""
        result = ScanResult(scanner_name=self.scanner.name)

        # Find and scan config file first
        config_path = ShardedModelDetector.find_model_config(self.file_path)
        if config_path:
            logger.debug(f"Model configuration detected: {config_path}")
            # Quick scan of config for metadata
            try:
                flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                config_fd = os.open(config_path, flags)
                try:
                    if not stat.S_ISREG(os.fstat(config_fd).st_mode):
                        raise OSError("Model configuration is not a regular file")
                    config_content = os.read(config_fd, 10240).decode("utf-8", errors="replace")
                finally:
                    os.close(config_fd)
                if "torch_dtype" in config_content:
                    result.add_check(
                        name="PyTorch Configuration Detection",
                        passed=True,
                        message="PyTorch model configuration detected",
                        severity=IssueSeverity.INFO,
                        location=config_path,
                        details={"config_file": config_path},
                    )
            except Exception as e:
                logger.warning(f"Failed to read config file: {e}")

        # Scan shards in parallel
        shard_scan_success = True
        if self.shard_info:
            scanner_config = getattr(self.scanner, "config", None)
            parallel_scanner = ParallelShardHandler(
                self.shard_info,
                self.scanner.__class__,
                scanner_config=dict(scanner_config) if isinstance(scanner_config, dict) else None,
            )
            shard_results = parallel_scanner.scan_shards(self.progress_callback)
            shard_scan_success = bool(shard_results.success)
            result.merge(shard_results)
            missing_count = self.shard_info.get("missing_shard_count")
            unreadable_count = self.shard_info.get("unreadable_shard_count")
            out_of_scope_count = self.shard_info.get("out_of_scope_shard_count")
            unvalidated_count = self.shard_info.get("unvalidated_shard_count")
            if isinstance(missing_count, int) and missing_count > 0:
                _mark_inconclusive_scan_outcome(result, "missing_model_shards")
            if isinstance(out_of_scope_count, int) and out_of_scope_count > 0:
                _mark_inconclusive_scan_outcome(result, "out_of_scope_model_shards")
            if isinstance(unreadable_count, int) and unreadable_count > 0:
                _mark_inconclusive_scan_outcome(result, "unreadable_model_shards")
            if isinstance(unvalidated_count, int) and unvalidated_count > 0:
                _mark_inconclusive_scan_outcome(result, "unvalidated_model_shards")
            if isinstance(missing_count, int) and missing_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(f"Missing {missing_count} expected model shard(s); scan coverage is incomplete."),
                    severity=IssueSeverity.INFO,
                    details={
                        "expected_total_shards": self.shard_info.get("expected_total_shards"),
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "missing_shard_count": missing_count,
                        "missing_shard_indices": self.shard_info.get("missing_shard_indices", []),
                        "missing_shard_indices_truncated": self.shard_info.get(
                            "missing_shard_indices_truncated", False
                        ),
                        "unreadable_shard_count": self.shard_info.get("unreadable_shard_count", 0),
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "out_of_scope_shard_count": self.shard_info.get("out_of_scope_shard_count", 0),
                        "out_of_scope_shards": self.shard_info.get("out_of_scope_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "missing_model_shards",
                    },
                )
            elif isinstance(out_of_scope_count, int) and out_of_scope_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Skipped {out_of_scope_count} model shard(s) resolving outside the direct scan directory; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "out_of_scope_shard_count": out_of_scope_count,
                        "out_of_scope_shards": self.shard_info.get("out_of_scope_shards", []),
                        "unreadable_shard_count": self.shard_info.get("unreadable_shard_count", 0),
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "out_of_scope_model_shards",
                    },
                )
            elif isinstance(unreadable_count, int) and unreadable_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=f"Unable to read {unreadable_count} model shard(s); scan coverage is incomplete.",
                    severity=IssueSeverity.INFO,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "unreadable_shard_count": unreadable_count,
                        "unreadable_shards": self.shard_info.get("unreadable_shards", []),
                        "unvalidated_shard_count": self.shard_info.get("unvalidated_shard_count", 0),
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unreadable_model_shards",
                    },
                )
            elif isinstance(unvalidated_count, int) and unvalidated_count > 0:
                result.add_check(
                    name="Sharded Model Coverage Check",
                    passed=False,
                    message=(
                        f"Skipped {unvalidated_count} model shard(s) outside the validated family; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    details={
                        "present_total_shards": self.shard_info.get("total_shards"),
                        "unvalidated_shard_count": unvalidated_count,
                        "unvalidated_shards": self.shard_info.get("unvalidated_shards", []),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unvalidated_model_shards",
                    },
                )
        result.finish(success=shard_scan_success and not result.has_errors and "scan_outcome" not in result.metadata)
        return result

    def _scan_with_mmap(self) -> "ScanResult":
        """Scan using memory mapping."""
        if not self._supports_bounded_large_file_analysis():
            return self._fail_closed_large_file_coverage(threshold_bytes=EXTREME_MODEL_THRESHOLD)

        mmap_scanner = MemoryMappedHandler(self.file_path, self.scanner)
        return mmap_scanner.scan_with_mmap(self.progress_callback)

    def _scan_large_file_distributed(self) -> "ScanResult":
        from ...scanner_results import IssueSeverity, ScanResult

        """Scan very large files using only bounded, scanner-aware analysis."""
        logger.debug(f"Scanning file ({self.total_size:,} bytes) with bounded large-file analysis")

        if not self._supports_bounded_large_file_analysis():
            return self._fail_closed_large_file_coverage(threshold_bytes=LARGE_MODEL_THRESHOLD_200GB)

        result = ScanResult(scanner_name=self.scanner.name)
        strategy = (
            "scanner-defined memory-mapped analysis"
            if hasattr(self.scanner, "_scan_with_mmap")
            else "memory-mapped chunk analysis"
        )
        result.add_check(
            name="Large File Detection",
            passed=True,
            message=f"Scanning file ({self.total_size:,} bytes) - processing may take additional time",
            severity=IssueSeverity.INFO,
            details={
                "file_size": self.total_size,
                "strategy": strategy,
                "note": "Bounded analysis enabled for this scanner",
            },
        )

        mmap_scanner = MemoryMappedHandler(self.file_path, self.scanner)
        if hasattr(self.scanner, "_scan_with_mmap"):
            scan_result = self.scanner._scan_with_mmap(self.file_path, self.progress_callback)
        else:
            scan_result = mmap_scanner.scan_with_mmap(self.progress_callback)

        result.merge(scan_result)
        result.finish(success=bool(scan_result.success))
        return result


def should_use_advanced_handler(file_path: str, *, allowed_shard_paths: list[str] | None = None) -> bool:
    """
    Check if file should use advanced file handler.

    Args:
        file_path: Path to check
        allowed_shard_paths: Validated shard targets permitted during grouped directory scans

    Returns:
        True if advanced handler should be used
    """
    if _grouped_shard_boundary_error(file_path, allowed_shard_paths) is not None:
        return True

    # Check for sharded model
    if ShardedModelDetector.detect_shards(file_path, allowed_paths=allowed_shard_paths):
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
    progress_callback: Callable[[str, float], None] | None = None,
    timeout: int = 7200,
    allowed_shard_paths: list[str] | None = None,
) -> "ScanResult":
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

    boundary_error = _grouped_shard_boundary_error(file_path, allowed_shard_paths)
    if boundary_error is not None:
        return _shard_boundary_failure_result(scanner.name, file_path, boundary_error)

    if should_bypass_cache_for_safetensors_header_limit(file_path, config):
        logger.debug(f"Bypassing advanced-file cache for bounded SafeTensors header failure: {file_path}")
        return scanner.scan(file_path)  # type: ignore[no-any-return]

    # A representative-file cache key cannot safely describe sibling shard
    # targets, identities, or coverage changes. Re-evaluate sharded families on
    # every scan so retargeted aliases and missing members fail closed.
    if ShardedModelDetector.detect_shards(file_path, allowed_paths=allowed_shard_paths) is not None:
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
        )

    # If caching is disabled, proceed with direct scan
    if not cache_enabled:
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
        )

    # Use cache manager for advanced large file scans
    try:
        from ...cache import get_cache_manager
        from ...cache.optimized_config import build_cache_version_context

        cache_manager = get_cache_manager(cache_dir, enabled=True)
        version_config = dict(config)
        if allowed_shard_paths is not None:
            # The allowlist changes shard expansion, so direct advanced scans need distinct cache keys.
            version_config["advanced_allowed_shard_paths"] = sorted(
                {str(Path(path).resolve()) for path in allowed_shard_paths}
            )
        version_context = build_cache_version_context(version_config)

        # Create wrapper function for cache manager
        def cached_advanced_scan_wrapper(fpath: str) -> dict:
            result = _scan_advanced_large_file_internal(
                fpath,
                scanner,
                progress_callback,
                timeout,
                allowed_shard_paths=allowed_shard_paths,
            )
            return result.to_dict()

        # Get cached result or perform scan
        result_dict = cache_manager.cached_scan(
            file_path,
            cached_advanced_scan_wrapper,
            version_context=version_context,
        )

        # Convert back to ScanResult
        from ...utils.helpers.result_conversion import scan_result_from_dict

        return scan_result_from_dict(result_dict)  # type: ignore[no-any-return]

    except Exception as e:
        # If cache system fails, fall back to direct scanning
        logger.warning(f"Advanced file cache error for {file_path}: {e}. Falling back to direct scan.")
        return _scan_advanced_large_file_internal(
            file_path,
            scanner,
            progress_callback,
            timeout,
            allowed_shard_paths=allowed_shard_paths,
        )


def _scan_advanced_large_file_internal(
    file_path: str,
    scanner: Any,
    progress_callback: Callable[[str, float], None] | None = None,
    timeout: int = 7200,
    allowed_shard_paths: list[str] | None = None,
) -> "ScanResult":
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
    handler = AdvancedFileHandler(
        file_path,
        scanner,
        progress_callback,
        timeout,
        allowed_shard_paths=allowed_shard_paths,
    )
    return handler.scan()
