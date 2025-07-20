"""
Parallel scanning functionality for ModelAudit.

This module provides parallel file scanning capabilities to improve performance
when scanning directories with multiple files.
"""

import concurrent.futures
import logging
import multiprocessing
import os
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from modelaudit.interrupt_handler import is_interrupted
from modelaudit.scanners.base import IssueSeverity

logger = logging.getLogger("modelaudit.parallel_scanner")


@dataclass
class WorkItem:
    """Represents a file to be scanned."""

    file_path: str
    config: dict[str, Any]


@dataclass
class WorkResult:
    """Result from scanning a single file."""

    file_path: str
    success: bool
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    duration: float = 0.0


@dataclass
class ParallelScanProgress:
    """Tracks progress of parallel scan."""

    total_files: int
    completed_files: int = 0
    active_workers: dict[int, str] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)

    @property
    def percentage(self) -> float:
        """Calculate completion percentage."""
        if self.total_files == 0:
            return 100.0
        return (self.completed_files / self.total_files) * 100

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time

    def estimate_remaining_time(self) -> Optional[float]:
        """Estimate remaining time in seconds."""
        if self.completed_files == 0:
            return None
        rate = self.completed_files / self.elapsed_time
        remaining = self.total_files - self.completed_files
        return remaining / rate if rate > 0 else None


def _scan_file_worker(work_item: WorkItem) -> WorkResult:
    """
    Worker function to scan a single file.

    This runs in a separate process and must be picklable.
    """
    start_time = time.time()

    try:
        # Import inside worker to ensure clean process state
        from modelaudit.core import scan_file

        result = scan_file(work_item.file_path, work_item.config)

        # Convert ScanResult to dict for serialization
        result_dict = {
            "scanner_name": result.scanner_name,
            "success": result.success,
            "issues": [issue.to_dict() for issue in result.issues],
            "bytes_scanned": result.bytes_scanned,
            "metadata": result.metadata,
        }

        return WorkResult(
            file_path=work_item.file_path,
            success=True,
            result=result_dict,
            duration=time.time() - start_time,
        )

    except Exception as e:
        error_details = {
            "type": type(e).__name__,
            "message": str(e),
            "traceback": traceback.format_exc(),
        }
        logger.error(f"Error scanning {work_item.file_path}: {e}", exc_info=True)
        return WorkResult(
            file_path=work_item.file_path,
            success=False,
            error=str(error_details),
            duration=time.time() - start_time,
        )


class ParallelScanner:
    """Manages parallel scanning of multiple files."""

    def __init__(
        self,
        max_workers: Optional[int] = None,
        timeout_per_file: int = 300,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ):
        """
        Initialize parallel scanner.

        Args:
            max_workers: Maximum number of worker processes (None = CPU count)
            timeout_per_file: Timeout in seconds for each file scan
            progress_callback: Optional callback for progress updates
        """
        # Validate and set max_workers
        cpu_count = multiprocessing.cpu_count()
        if max_workers is None:
            self.max_workers = cpu_count
        else:
            # Ensure max_workers is within reasonable bounds
            if max_workers < 1:
                logger.warning(f"max_workers ({max_workers}) is less than 1, setting to 1")
                self.max_workers = 1
            elif max_workers > cpu_count * 4:
                # Allow oversubscription but warn if excessive
                logger.warning(f"max_workers ({max_workers}) is more than 4x CPU count ({cpu_count})")
                self.max_workers = max_workers
            else:
                self.max_workers = max_workers

        self.timeout_per_file = timeout_per_file
        self.progress_callback = progress_callback
        self._progress: Optional[ParallelScanProgress] = None

    def scan_files(
        self,
        file_paths: list[str],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Scan multiple files in parallel.

        Args:
            file_paths: List of file paths to scan
            config: Scanner configuration

        Returns:
            Aggregated scan results
        """
        if not file_paths:
            return self._create_empty_results()

        # Initialize progress tracking
        self._progress = ParallelScanProgress(total_files=len(file_paths))

        # Use sequential scanning for small file counts
        # Process creation overhead makes parallel scanning inefficient for < 10 files
        if len(file_paths) < 10 or self.max_workers == 1:
            logger.debug(f"Using sequential scanning for {len(file_paths)} files")
            return self._scan_sequential(file_paths, config)

        logger.info(f"Starting parallel scan of {len(file_paths)} files with {self.max_workers} workers")

        # Create work items
        work_items = [WorkItem(file_path, config) for file_path in file_paths]

        # Initialize results
        results = self._create_empty_results()
        results["start_time"] = time.time()

        # Process files in parallel
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all work
            future_to_work = {executor.submit(_scan_file_worker, item): item for item in work_items}

            # Process results as they complete
            # Calculate a reasonable overall timeout based on number of files and workers
            # Allow at least timeout_per_file for each batch of files that can run in parallel
            # Add 20% buffer for overhead
            # Cap the timeout to a reasonable maximum (e.g., 1 hour)
            batches = (len(work_items) + self.max_workers - 1) // self.max_workers
            calculated_timeout = int(batches * self.timeout_per_file * 1.2)
            # Cap at 1 hour to prevent excessive wait times
            overall_timeout = min(calculated_timeout, 3600)
            logger.debug(
                f"Calculated overall timeout: {overall_timeout}s for {len(work_items)} files "
                f"with {self.max_workers} workers (capped from {calculated_timeout}s)"
            )

            try:
                for future in as_completed(future_to_work, timeout=overall_timeout):
                    # Check for interrupt
                    if is_interrupted():
                        logger.info("Parallel scan interrupted by user")
                        # Cancel remaining futures
                        for f in future_to_work:
                            f.cancel()
                        results["issues"].append(
                            {
                                "message": "Scan interrupted by user",
                                "severity": IssueSeverity.INFO.value,
                                "location": "",
                                "details": {"interrupted": True},
                            }
                        )
                        break

                    work_item = future_to_work[future]

                    try:
                        work_result = future.result(timeout=self.timeout_per_file)
                        self._process_work_result(results, work_result)

                    except Exception as e:
                        logger.error(f"Worker failed for {work_item.file_path}: {e}")
                        self._add_scan_error(results, work_item.file_path, str(e))

                    finally:
                        # Update progress
                        if self._progress:
                            self._progress.completed_files += 1
                            if self.progress_callback:
                                self._report_progress()

            except concurrent.futures.TimeoutError:
                logger.error(f"Overall scan timeout reached after {overall_timeout}s")
                # Process any completed results
                for future in future_to_work:
                    if future.done():
                        try:
                            work_result = future.result(timeout=0)
                            self._process_work_result(results, work_result)
                        except Exception:
                            pass  # Already logged or timed out
                    else:
                        future.cancel()

                results["issues"].append(
                    {
                        "message": f"Scan timeout reached after {overall_timeout}s",
                        "severity": IssueSeverity.WARNING.value,
                        "location": "",
                        "details": {"timeout": overall_timeout, "completed": results.get("files_scanned", 0)},
                    }
                )

        # Finalize results
        results["finish_time"] = time.time()
        results["duration"] = results["finish_time"] - results["start_time"]
        results["parallel_scan"] = True
        results["worker_count"] = self.max_workers

        return results

    def _scan_sequential(
        self,
        file_paths: list[str],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Fallback to sequential scanning."""
        results = self._create_empty_results()
        results["start_time"] = time.time()

        for i, file_path in enumerate(file_paths):
            # Check for interrupt
            if is_interrupted():
                logger.info("Sequential scan interrupted by user")
                results["issues"].append(
                    {
                        "message": "Scan interrupted by user",
                        "severity": IssueSeverity.INFO.value,
                        "location": "",
                        "details": {"interrupted": True},
                    }
                )
                break

            if self.progress_callback:
                self.progress_callback(
                    f"Scanning file {i + 1}/{len(file_paths)}: {os.path.basename(file_path)}",
                    (i / len(file_paths)) * 100,
                )

            work_item = WorkItem(file_path, config)
            work_result = _scan_file_worker(work_item)
            self._process_work_result(results, work_result)

        results["finish_time"] = time.time()
        results["duration"] = results["finish_time"] - results["start_time"]
        results["parallel_scan"] = False

        return results

    def _process_work_result(
        self,
        results: dict[str, Any],
        work_result: WorkResult,
    ) -> None:
        """Process a single work result and aggregate into results."""
        if work_result.success and work_result.result:
            # Aggregate scan results
            result_data = work_result.result

            # Update counters
            results["bytes_scanned"] += result_data.get("bytes_scanned", 0)
            results["files_scanned"] += 1

            # Track scanner names
            scanner_name = result_data.get("scanner_name")
            if scanner_name and scanner_name not in results["scanners"]:
                results["scanners"].append(scanner_name)

            # Add issues
            for issue in result_data.get("issues", []):
                results["issues"].append(issue)

            # Add to assets
            asset_entry = {
                "path": work_result.file_path,
                "type": scanner_name,
                "scanned": True,
                "scanner": scanner_name,
            }

            # Add metadata keys if available
            metadata = result_data.get("metadata", {})
            if "keys" in metadata:
                asset_entry["keys"] = metadata["keys"]
            if "file_size" in metadata:
                asset_entry["size"] = metadata["file_size"]
            if "tensors" in metadata:
                asset_entry["tensors"] = metadata["tensors"]
            if "contents" in metadata:
                asset_entry["contents"] = metadata["contents"]

            results["assets"].append(asset_entry)

            # Store metadata
            results["file_metadata"][work_result.file_path] = result_data.get("metadata", {})

        else:
            # Handle scan failure
            self._add_scan_error(results, work_result.file_path, work_result.error or "Unknown error")

    def _add_scan_error(
        self,
        results: dict[str, Any],
        file_path: str,
        error: str,
    ) -> None:
        """Add an error entry for a failed file scan."""
        results["issues"].append(
            {
                "message": f"Error scanning file: {error}",
                "severity": IssueSeverity.WARNING.value,
                "location": file_path,
                "details": {
                    "error": error,
                    "parallel_scan": True,
                },
            }
        )

        results["assets"].append(
            {
                "path": file_path,
                "type": "error",
                "scanned": False,
            }
        )

        results["has_errors"] = True

    def _report_progress(self) -> None:
        """Report current progress via callback."""
        if not self._progress or not self.progress_callback:
            return

        # Build progress message
        remaining_time = self._progress.estimate_remaining_time()
        eta_str = f", ETA: {int(remaining_time)}s" if remaining_time else ""

        message = (
            f"Scanning files: {self._progress.completed_files}/{self._progress.total_files} "
            f"({self._progress.percentage:.1f}%{eta_str})"
        )

        self.progress_callback(message, self._progress.percentage)

    def _create_empty_results(self) -> dict[str, Any]:
        """Create an empty results dictionary."""
        return {
            "bytes_scanned": 0,
            "issues": [],
            "files_scanned": 0,
            "scanners": [],
            "assets": [],
            "file_metadata": {},
            "has_errors": False,
            "success": True,
        }
