import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from modelaudit.scanners import SCANNER_REGISTRY
from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.utils.filetype import detect_file_format

logger = logging.getLogger("modelaudit.core")


def scan_model_directory_or_file(
    path: str,
    blacklist_patterns: Optional[List[str]] = None,
    timeout: int = 300,
    max_file_size: int = 0,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Scan a model file or directory for malicious content.

    Args:
        path: Path to the model file or directory
        blacklist_patterns: Additional blacklist patterns to check against
            model names
        timeout: Scan timeout in seconds
        max_file_size: Maximum file size to scan in bytes
        progress_callback: Optional callback function to report progress
            (message, percentage)
        **kwargs: Additional arguments to pass to scanners

    Returns:
        Dictionary with scan results
    """
    # Start timer for timeout
    start_time = time.time()

    # Initialize results
    results = {
        "start_time": start_time,
        "path": path,
        "bytes_scanned": 0,
        "issues": [],
        "success": True,
        "files_scanned": 0,
        "scanners": [],  # Track the scanners used
    }

    # Configure scan options
    config = {
        "blacklist_patterns": blacklist_patterns,
        "max_file_size": max_file_size,
        "timeout": timeout,
        **kwargs,
    }

    try:
        # Check if path exists
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path does not exist: {path}")

        # Check if path is readable
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Path is not readable: {path}")

        # Check if path is a directory
        if os.path.isdir(path):
            if progress_callback:
                progress_callback(f"Scanning directory: {path}", 0.0)

            # Scan all files in the directory
            total_files = sum(1 for _ in Path(path).rglob("*") if _.is_file())
            processed_files = 0

            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)

                    # Check timeout
                    if time.time() - start_time > timeout:
                        msg = f"Scan timeout after {timeout} seconds"
                        raise TimeoutError(msg)

                    # Update progress
                    if progress_callback and total_files > 0:
                        processed_files += 1
                        msg = (
                            f"Scanning file {processed_files}/{total_files}: " f"{file}"
                        )
                        progress_callback(
                            msg,
                            processed_files / total_files * 100,
                        )

                    # Scan the file
                    try:
                        file_result = scan_file(file_path, config)
                        results["bytes_scanned"] += file_result.bytes_scanned
                        results["files_scanned"] += 1  # Increment file count

                        # Track scanner name
                        scanner_name = file_result.scanner_name
                        if scanner_name and scanner_name not in results["scanners"]:
                            results["scanners"].append(scanner_name)

                        # Add issues from file scan
                        for issue in file_result.issues:
                            results["issues"].append(issue.to_dict())
                    except Exception as e:
                        logger.warning(f"Error scanning file {file_path}: {str(e)}")
                        # Add as an issue
                        results["issues"].append(
                            {
                                "message": f"Error scanning file: {str(e)}",
                                "severity": IssueSeverity.WARNING.value,
                                "location": file_path,
                                "details": {"exception_type": type(e).__name__},
                            }
                        )
        else:
            # Scan a single file
            if progress_callback:
                progress_callback(f"Scanning file: {path}", 0.0)

            # Get file size for progress reporting
            file_size = os.path.getsize(path)
            results["files_scanned"] = 1  # Single file scan

            # Create a wrapper for the file to report progress
            if progress_callback and file_size > 0:
                original_open = open

                def progress_open(file_path, mode="r", *args, **kwargs):
                    file = original_open(file_path, mode, *args, **kwargs)
                    file_pos = 0

                    # Override read method to report progress
                    original_read = file.read

                    def progress_read(size=-1):
                        nonlocal file_pos
                        data = original_read(size)
                        file_pos += len(data)
                        progress_callback(
                            f"Reading file: {os.path.basename(file_path)}",
                            min(file_pos / file_size * 100, 100),
                        )
                        return data

                    file.read = progress_read
                    return file

                # Monkey patch open temporarily
                import builtins

                original_builtins_open = builtins.open
                builtins.open = progress_open

                try:
                    file_result = scan_file(path, config)
                finally:
                    # Restore original open
                    builtins.open = original_builtins_open
            else:
                file_result = scan_file(path, config)

            results["bytes_scanned"] += file_result.bytes_scanned

            # Track scanner name
            scanner_name = file_result.scanner_name
            if scanner_name and scanner_name not in results["scanners"]:
                results["scanners"].append(scanner_name)

            # Add issues from file scan
            for issue in file_result.issues:
                results["issues"].append(issue.to_dict())

            if progress_callback:
                progress_callback(f"Completed scanning: {path}", 100.0)

    except Exception as e:
        logger.exception(f"Error during scan: {str(e)}")
        results["success"] = False
        issue = {
            "message": f"Error during scan: {str(e)}",
            "severity": IssueSeverity.ERROR.value,
            "details": {"exception_type": type(e).__name__},
        }
        results["issues"].append(issue)

    # Add final timing information
    results["finish_time"] = time.time()
    results["duration"] = results["finish_time"] - results["start_time"]
    error_issues = [
        issue
        for issue in results["issues"]
        if (
            isinstance(issue, dict)
            and "severity" in issue
            and issue.get("severity") == IssueSeverity.ERROR.value
        )
    ]
    results["has_errors"] = len(error_issues) > 0

    return results


def scan_file(path: str, config: Dict[str, Any] = None) -> ScanResult:
    """
    Scan a single file with the appropriate scanner.

    Args:
        path: Path to the file to scan
        config: Optional scanner configuration

    Returns:
        ScanResult object with the scan results
    """
    if config is None:
        config = {}

    # Check file size first
    max_file_size = config.get("max_file_size", 0)  # Default unlimited
    try:
        file_size = os.path.getsize(path)
        if max_file_size > 0 and file_size > max_file_size:
            sr = ScanResult(scanner_name="size_check")
            msg = (
                f"File too large to scan: {file_size} bytes " f"(max: {max_file_size})"
            )
            sr.add_issue(
                msg,
                severity=IssueSeverity.WARNING,
                details={
                    "file_size": file_size,
                    "max_file_size": max_file_size,
                    "path": path,
                },
            )
            return sr
    except OSError as e:
        sr = ScanResult(scanner_name="error")
        sr.add_issue(
            f"Error checking file size: {e}",
            severity=IssueSeverity.ERROR,
            details={"error": str(e), "path": path},
        )
        return sr

    logger.info(f"Scanning file: {path}")

    # Try to use scanners from the registry
    for scanner_class in SCANNER_REGISTRY:
        if scanner_class.can_handle(path):
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)
            return scanner.scan(path)

    # If no scanner could handle the file, create a default unknown format result
    format_ = detect_file_format(path)
    sr = ScanResult(scanner_name="unknown")
    sr.add_issue(
        f"Unknown or unhandled format: {format_}",
        severity=IssueSeverity.DEBUG,
        details={"format": format_, "path": path},
    )
    return sr


def merge_scan_result(
    results: Dict[str, Any], scan_result: ScanResult
) -> Dict[str, Any]:
    """
    Merge a ScanResult object into the results dictionary.

    Args:
        results: The existing results dictionary
        scan_result: The ScanResult object to merge

    Returns:
        The updated results dictionary
    """
    # Convert scan_result to dict if it's a ScanResult object
    if isinstance(scan_result, ScanResult):
        scan_dict = scan_result.to_dict()
    else:
        scan_dict = scan_result

    # Merge issues
    for issue in scan_dict.get("issues", []):
        results["issues"].append(issue)

    # Update bytes scanned
    results["bytes_scanned"] += scan_dict.get("bytes_scanned", 0)

    # Update scanner info if not already set
    if "scanner_name" not in results and "scanner" in scan_dict:
        results["scanner_name"] = scan_dict["scanner"]

    # Set success to False if any scan failed
    if not scan_dict.get("success", True):
        results["success"] = False

    return results
