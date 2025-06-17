import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Optional, cast

from modelaudit.scanners import SCANNER_REGISTRY
from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.utils.filetype import detect_file_format

logger = logging.getLogger("modelaudit.core")


def scan_model_directory_or_file(
    path: str,
    blacklist_patterns: Optional[list[str]] = None,
    timeout: int = 300,
    max_file_size: int = 0,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    **kwargs,
) -> dict[str, Any]:
    """
    Scan a model file or directory for malicious content.

    Args:
        path: Path to the model file or directory
        blacklist_patterns: Additional blacklist patterns to check against model names
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

    # Initialize results with proper type hints
    results: dict[str, Any] = {
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
                        raise TimeoutError(f"Scan timeout after {timeout} seconds")

                    # Update progress
                    if progress_callback and total_files > 0:
                        processed_files += 1
                        progress_callback(
                            f"Scanning file {processed_files}/{total_files}: {file}",
                            processed_files / total_files * 100,
                        )

                    # Scan the file
                    try:
                        file_result = scan_file(file_path, config)
                        # Use cast to help mypy understand the types
                        results["bytes_scanned"] = (
                            cast(int, results["bytes_scanned"])
                            + file_result.bytes_scanned
                        )
                        results["files_scanned"] = (
                            cast(int, results["files_scanned"]) + 1
                        )  # Increment file count

                        # Track scanner name
                        scanner_name = file_result.scanner_name
                        scanners_list = cast(list[str], results["scanners"])
                        if scanner_name and scanner_name not in scanners_list:
                            scanners_list.append(scanner_name)

                        # Add issues from file scan
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        for issue in file_result.issues:
                            issues_list.append(issue.to_dict())
                    except Exception as e:
                        logger.warning(f"Error scanning file {file_path}: {str(e)}")
                        # Add as an issue
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        issues_list.append(
                            {
                                "message": f"Error scanning file: {str(e)}",
                                "severity": IssueSeverity.WARNING.value,
                                "location": file_path,
                                "details": {"exception_type": type(e).__name__},
                            },
                        )
        else:
            # Scan a single file
            if progress_callback:
                progress_callback(f"Scanning file: {path}", 0.0)

            # Get file size for progress reporting
            file_size = os.path.getsize(path)
            results["files_scanned"] = 1  # Single file scan

            # Create a wrapper for the file to report progress
            if progress_callback is not None and file_size > 0:
                import builtins
                from typing import IO

                original_builtins_open = builtins.open

                def progress_open(
                    file_path: str,
                    mode: str = "r",
                    *args,
                    **kwargs,
                ) -> IO[Any]:
                    file = original_builtins_open(file_path, mode, *args, **kwargs)
                    file_pos = 0

                    # Override read method to report progress
                    original_read = file.read

                    def progress_read(size: int = -1) -> Any:
                        nonlocal file_pos
                        data = original_read(size)
                        if isinstance(data, (str, bytes)):
                            file_pos += len(data)
                        if progress_callback is not None:
                            progress_callback(
                                f"Reading file: {os.path.basename(file_path)}",
                                min(file_pos / file_size * 100, 100),
                            )
                        return data

                    file.read = progress_read  # type: ignore[method-assign]
                    return file

                # Monkey patch open temporarily
                builtins.open = progress_open  # type: ignore

                try:
                    file_result = scan_file(path, config)
                finally:
                    # Restore original open
                    builtins.open = original_builtins_open
            else:
                file_result = scan_file(path, config)

            results["bytes_scanned"] = (
                cast(int, results["bytes_scanned"]) + file_result.bytes_scanned
            )

            # Track scanner name
            scanner_name = file_result.scanner_name
            scanners_list = cast(list[str], results["scanners"])
            if scanner_name and scanner_name not in scanners_list:
                scanners_list.append(scanner_name)

            # Add issues from file scan
            issues_list = cast(list[dict[str, Any]], results["issues"])
            for issue in file_result.issues:
                issues_list.append(issue.to_dict())

            if progress_callback:
                progress_callback(f"Completed scanning: {path}", 100.0)

    except Exception as e:
        logger.exception(f"Error during scan: {str(e)}")
        results["success"] = False
        issue_dict = {
            "message": f"Error during scan: {str(e)}",
            "severity": IssueSeverity.CRITICAL.value,
            "details": {"exception_type": type(e).__name__},
        }
        issues_list = cast(list[dict[str, Any]], results["issues"])
        issues_list.append(issue_dict)

    # Add final timing information
    results["finish_time"] = time.time()
    results["duration"] = cast(float, results["finish_time"]) - cast(
        float,
        results["start_time"],
    )

    # Determine if there were operational scan errors vs security findings
    # has_errors should only be True for operational errors (scanner crashes,
    # file not found, etc.) not for security findings detected in models
    operational_error_indicators = [
        # Scanner execution errors
        "Error during scan",
        "Error checking file size",
        "Error scanning file",
        "Scanner crashed",
        "Scan timeout",
        # File system errors
        "Path does not exist",
        "Path is not readable",
        "Permission denied",
        "File not found",
        # Dependency/environment errors
        "not installed, cannot scan",
        "Missing dependency",
        "Import error",
        "Module not found",
        # File format/corruption errors
        "not a valid",
        "Invalid file format",
        "Corrupted file",
        "Bad file signature",
        "Unable to parse",
        # Resource/system errors
        "Out of memory",
        "Disk space",
        "Too many open files",
    ]

    issues_list = cast(list[dict[str, Any]], results["issues"])
    results["has_errors"] = (
        any(
            any(
                indicator in issue.get("message", "")
                for indicator in operational_error_indicators
            )
            for issue in issues_list
            if isinstance(issue, dict)
            and issue.get("severity") == IssueSeverity.CRITICAL.value
        )
        or not results["success"]
    )

    return results


def determine_exit_code(results: dict[str, Any]) -> int:
    """
    Determine the appropriate exit code based on scan results.

    Exit codes:
    - 0: Success, no security issues found
    - 1: Security issues found (scan completed successfully)
    - 2: Operational errors occurred during scanning

    Args:
        results: Dictionary with scan results

    Returns:
        Exit code (0, 1, or 2)
    """
    # Check for operational errors first (highest priority)
    if results.get("has_errors", False):
        return 2

    # Check for any security findings (warnings, errors, or info issues)
    issues = results.get("issues", [])
    if issues:
        # Filter out DEBUG level issues for exit code determination
        non_debug_issues = [
            issue
            for issue in issues
            if isinstance(issue, dict) and issue.get("severity") != "debug"
        ]
        if non_debug_issues:
            return 1

    # No issues found
    return 0


def scan_file(path: str, config: dict[str, Any] = None) -> ScanResult:
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
            sr.add_issue(
                f"File too large to scan: {file_size} bytes (max: {max_file_size})",
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
            severity=IssueSeverity.CRITICAL,
            details={"error": str(e), "path": path},
        )
        return sr

    logger.info(f"Scanning file: {path}")

    # Try to use scanners from the registry
    for scanner_class in SCANNER_REGISTRY:
        # These are concrete scanner classes, not the abstract BaseScanner
        if scanner_class.can_handle(path):
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)  # type: ignore[abstract]
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
    results: dict[str, Any],
    scan_result: ScanResult,
) -> dict[str, Any]:
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
    issues_list = cast(list[dict[str, Any]], results["issues"])
    for issue in scan_dict.get("issues", []):
        issues_list.append(issue)

    # Update bytes scanned
    results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + scan_dict.get(
        "bytes_scanned",
        0,
    )

    # Update scanner info if not already set
    if "scanner_name" not in results and "scanner" in scan_dict:
        results["scanner_name"] = scan_dict["scanner"]

    # Set success to False if any scan failed
    if not scan_dict.get("success", True):
        results["success"] = False

    return results
