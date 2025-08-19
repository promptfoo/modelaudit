import builtins
import hashlib
import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import IO, Any, Callable, Optional, cast
from unittest.mock import patch

from modelaudit.interrupt_handler import check_interrupted
from modelaudit.license_checker import (
    LICENSE_FILES,
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.scanners import _registry
from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult
from modelaudit.utils import is_within_directory, resolve_dvc_file, should_skip_file
from modelaudit.utils.advanced_file_handler import (
    scan_advanced_large_file,
    should_use_advanced_handler,
)
from modelaudit.utils.assets import asset_from_scan_result
from modelaudit.utils.filetype import (
    detect_file_format,
    detect_file_format_from_magic,
    detect_format_from_extension,
    validate_file_type,
)
from modelaudit.utils.large_file_handler import (
    scan_large_file,
    should_use_large_file_handler,
)
from modelaudit.utils.streaming import stream_analyze_file

logger = logging.getLogger("modelaudit.core")

# Lock to ensure thread-safe monkey patching of builtins.open
_OPEN_PATCH_LOCK = Lock()


def _add_asset_to_results(
    results: dict[str, Any],
    file_path: str,
    file_result: ScanResult,
) -> None:
    """Helper function to add an asset entry to the results."""
    assets_list = cast(list[dict[str, Any]], results["assets"])
    assets_list.append(asset_from_scan_result(file_path, file_result))


def _add_error_asset_to_results(results: dict[str, Any], file_path: str) -> None:
    """Helper function to add an error asset entry to the results."""
    assets_list = cast(list[dict[str, Any]], results["assets"])
    assets_list.append({"path": file_path, "type": "error"})


def _calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file for deduplication purposes."""
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.warning(f"Failed to calculate hash for {file_path}: {e}")
        # Return a unique identifier based on file path and size as fallback
        try:
            file_size = os.path.getsize(file_path)
            return f"fallback_{file_path}_{file_size}"
        except Exception:
            return f"fallback_{file_path}"


def _group_files_by_content(file_paths: list[str]) -> dict[str, list[str]]:
    """Group files by their content hash to avoid scanning duplicates.

    Args:
        file_paths: List of file paths to group

    Returns:
        Dictionary mapping content hash to list of file paths with that content
    """
    content_groups: dict[str, list[str]] = defaultdict(list)

    for file_path in file_paths:
        content_hash = _calculate_file_hash(file_path)
        content_groups[content_hash].append(file_path)

    # Log information about duplicate content found
    for content_hash, paths in content_groups.items():
        if len(paths) > 1:
            logger.info(f"Found {len(paths)} files with identical content (hash: {content_hash[:16]}...)")
            for path in paths:
                logger.debug(f"  - {path}")

    return dict(content_groups)


def _consolidate_checks(results: dict[str, Any]) -> None:
    """Consolidate duplicate checks by name and asset for cleaner reporting.

    Groups checks by (check_name, primary_asset_path) and consolidates them into
    single checks per asset. This provides a cleaner reporting view while preserving
    all findings from thorough scanning.

    Args:
        results: Scan results dictionary containing 'checks' list

    Raises:
        Exception: Logs errors but doesn't fail the scan if consolidation fails
    """
    checks_list = cast(list[dict[str, Any]], results.get("checks", []))
    if not checks_list:
        logger.debug("No checks to consolidate")
        return

    logger.debug(f"Starting consolidation of {len(checks_list)} checks")

    # Validate input data
    if not isinstance(checks_list, list):
        logger.error(f"Invalid checks format: expected list, got {type(checks_list)}")
        return

    # Group checks by (check_name, primary_asset_path)
    check_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for i, check in enumerate(checks_list):
        if not isinstance(check, dict):
            logger.warning(f"Invalid check format at index {i}, skipping: {check}")
            continue

        check_name = check.get("name", "Unknown Check")
        location = check.get("location", "")

        # Extract primary asset path from location with robust parsing
        primary_asset = "unknown"
        if location and isinstance(location, str):
            # Split on spaces first to handle duplicate file listings
            locations = location.strip().split()
            if locations:
                primary_location = locations[0]
                # Extract main file path (before any ':' separator for archive contents)
                primary_asset = primary_location.split(":", 1)[0] if ":" in primary_location else primary_location

                # Normalize empty paths
                primary_asset = primary_asset.strip() if primary_asset.strip() else "unknown"

        group_key = (check_name, primary_asset)
        check_groups[group_key].append(check)

    # Consolidate checks within each group
    consolidated_checks: list[dict[str, Any]] = []

    for (check_name, primary_asset), group_checks in check_groups.items():
        if len(group_checks) == 1:
            # Single check - use as-is
            consolidated_checks.append(group_checks[0])
            continue

        # Multiple checks - consolidate them
        passed_count = sum(1 for c in group_checks if c.get("status") == "passed")
        failed_count = len(group_checks) - passed_count

        # Determine consolidated status
        consolidated_status = "failed" if failed_count > 0 else "passed"

        # Create consolidated message
        if consolidated_status == "passed":
            consolidated_message = group_checks[0].get("message", "Check passed")
            # If all checks have the same message, use it; otherwise make generic
            messages = {c.get("message", "") for c in group_checks}
            if len(messages) > 1:
                consolidated_message = f"{check_name} completed successfully"
        else:
            # For failed checks, create a summary message
            unique_messages = {c.get("message", "") for c in group_checks if c.get("status") == "failed"}
            if len(unique_messages) == 1:
                consolidated_message = next(iter(unique_messages))
            else:
                consolidated_message = f"{check_name} found {failed_count} issue(s)"

        # Collect all details from failed checks
        consolidated_details: dict[str, Any] = {"component_count": len(group_checks)}
        failed_details: list[Any] = []

        for check in group_checks:
            if check.get("status") == "failed" and check.get("details"):
                failed_details.append(check["details"])

        if failed_details:
            consolidated_details["findings"] = failed_details

        # Use the most recent timestamp with safety check
        timestamps = [c.get("timestamp", 0) for c in group_checks if isinstance(c.get("timestamp"), (int, float))]
        consolidated_timestamp = max(timestamps) if timestamps else time.time()

        # Get consolidated location (preserve duplicate file info if present)
        consolidated_location = group_checks[0].get("location", primary_asset)

        # Get severity and why from failed checks (if any)
        consolidated_severity = None
        consolidated_why = None
        for check in group_checks:
            if check.get("status") == "failed":
                if not consolidated_severity and check.get("severity"):
                    consolidated_severity = check["severity"]
                if not consolidated_why and check.get("why"):
                    consolidated_why = check["why"]

        # Create consolidated check
        consolidated_check = {
            "name": check_name,
            "status": consolidated_status,
            "message": consolidated_message,
            "location": consolidated_location,
            "details": consolidated_details,
            "timestamp": consolidated_timestamp,
        }

        # Add severity and why for failed checks
        if consolidated_severity:
            consolidated_check["severity"] = consolidated_severity
        if consolidated_why:
            consolidated_check["why"] = consolidated_why

        consolidated_checks.append(consolidated_check)

        # Log consolidation info
        if len(group_checks) > 1:
            logger.debug(
                f"Consolidated {len(group_checks)} '{check_name}' checks for {primary_asset} "
                f"({passed_count} passed, {failed_count} failed)"
            )

    # Replace the original checks list with consolidated checks
    results["checks"] = consolidated_checks

    # Update check counts with validation
    total_checks = len(consolidated_checks)
    passed_checks = sum(1 for c in consolidated_checks if c.get("status") == "passed")
    failed_checks = sum(1 for c in consolidated_checks if c.get("status") == "failed")
    skipped_checks = total_checks - passed_checks - failed_checks

    # Validate counts make sense
    if passed_checks + failed_checks + skipped_checks != total_checks:
        logger.warning(
            f"Check count mismatch: {passed_checks}P + {failed_checks}F + {skipped_checks}S != {total_checks}T"
        )

    results["total_checks"] = total_checks
    results["passed_checks"] = passed_checks
    results["failed_checks"] = failed_checks

    # Log consolidation summary
    reduction_count = len(checks_list) - total_checks
    logger.info(f"Check consolidation: {len(checks_list)} -> {total_checks} ({reduction_count} duplicates removed)")

    if skipped_checks > 0:
        logger.debug(f"Check status distribution: {passed_checks}P, {failed_checks}F, {skipped_checks}S")


def validate_scan_config(config: dict[str, Any]) -> None:
    """Validate configuration parameters for scanning."""
    timeout = config.get("timeout")
    if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
        raise ValueError("timeout must be a positive integer")

    max_file_size = config.get("max_file_size")
    if max_file_size is not None and (not isinstance(max_file_size, int) or max_file_size < 0):
        raise ValueError("max_file_size must be a non-negative integer")

    max_total_size = config.get("max_total_size")
    if max_total_size is not None and (not isinstance(max_total_size, int) or max_total_size < 0):
        raise ValueError("max_total_size must be a non-negative integer")

    chunk_size = config.get("chunk_size")
    if chunk_size is not None and (not isinstance(chunk_size, int) or chunk_size <= 0):
        raise ValueError("chunk_size must be a positive integer")


def scan_model_directory_or_file(
    path: str,
    blacklist_patterns: Optional[list[str]] = None,
    timeout: int = 1800,  # Increased to 30 minutes for large models (up to 8GB+)
    max_file_size: int = 0,  # 0 means unlimited - support any size
    max_total_size: int = 0,  # 0 means unlimited
    strict_license: bool = False,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    skip_file_types: bool = True,
    **kwargs,
) -> dict[str, Any]:
    """
    Scan a model file or directory for malicious content.

    Args:
        path: Path to the model file or directory
        blacklist_patterns: Additional blacklist patterns to check against model names
        timeout: Scan timeout in seconds
        max_file_size: Maximum file size to scan in bytes
        max_total_size: Maximum total bytes to scan across all files
        strict_license: Fail scan if incompatible licenses are found
        progress_callback: Optional callback function to report progress
                          (message, percentage)
        skip_file_types: Whether to skip non-model file types during directory scans
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
        "checks": [],  # Track all security checks performed
        "success": True,
        "files_scanned": 0,
        "scanners": [],  # Track the scanners used
        "assets": [],
        "file_metadata": {},  # Per-file metadata
    }

    # Configure scan options
    config = {
        "blacklist_patterns": blacklist_patterns,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "timeout": timeout,
        "skip_file_types": skip_file_types,
        "strict_license": strict_license,
        **kwargs,
    }

    validate_scan_config(config)

    try:
        # Handle streaming paths
        if path.startswith("stream://"):
            # Extract the actual URL
            stream_url = path[9:]  # Remove "stream://" prefix
            if progress_callback:
                progress_callback(f"Streaming analysis: {stream_url}", 0.0)

            # Perform streaming analysis
            from modelaudit.scanners import get_scanner_for_file

            scanner = get_scanner_for_file(stream_url, config=config)
            if scanner:
                scan_result, was_complete = stream_analyze_file(stream_url, scanner)
                if scan_result:
                    results["files_scanned"] = 1
                    results["bytes_scanned"] = scan_result.metadata.get("file_size", 0)

                    # Add scanner info
                    scanners_list = cast(list[str], results["scanners"])
                    if scan_result.scanner_name and scan_result.scanner_name not in scanners_list:
                        scanners_list.append(scan_result.scanner_name)

                    # Add issues
                    issues_list = cast(list[dict[str, Any]], results["issues"])
                    for issue in scan_result.issues:
                        issues_list.append(issue.to_dict())

                    # Add checks if available
                    if hasattr(scan_result, "checks"):
                        checks_list = cast(list[dict[str, Any]], results["checks"])
                        for check in scan_result.checks:
                            checks_list.append(check.to_dict())

                    # Add asset
                    _add_asset_to_results(results, stream_url, scan_result)

                    # Add metadata
                    file_meta = cast(dict[str, Any], results["file_metadata"])
                    file_meta[stream_url] = scan_result.metadata

                    if not was_complete:
                        issues_list.append(
                            {
                                "message": "Streaming analysis was partial - only analyzed file header",
                                "severity": IssueSeverity.INFO.value,
                                "location": stream_url,
                                "details": {"analysis_complete": False},
                            }
                        )
                else:
                    raise ValueError(f"Streaming analysis failed for {stream_url}")
            else:
                raise ValueError(f"No scanner available for {stream_url}")

            # Return early for streaming
            results["finish_time"] = time.time()
            results["duration"] = results["finish_time"] - results["start_time"]
            return results

        # Check if path exists (for non-streaming paths)
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
            # Use lazy file counting for better performance on large directories
            total_files = None  # Will be set to actual count if directory is small
            processed_files = 0
            limit_reached = False

            # Quick check: count files only if directory seems reasonable in size
            # This avoids the expensive rglob() on large directories
            try:
                # Do a quick count of immediate children first
                immediate_children = len(list(Path(path).iterdir()))
                if immediate_children < 1000:  # Only count if not too many immediate children
                    total_files = sum(1 for _ in Path(path).rglob("*") if _.is_file())
            except (OSError, PermissionError):
                # If we can't count, just proceed without progress percentage
                total_files = None

            base_dir = Path(path).resolve()
            scanned_paths: set[str] = set()

            # First pass: collect all file paths that need scanning
            files_to_scan: list[str] = []
            for root, _, files in os.walk(path, followlinks=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    resolved_file = Path(file_path).resolve()

                    # Check if this is a HuggingFace cache symlink scenario
                    is_hf_cache_symlink = False
                    if (
                        os.path.islink(file_path)
                        and ".cache/huggingface/hub" in str(base_dir)
                        and "/snapshots/" in str(file_path)
                    ):
                        try:
                            link_target = os.readlink(file_path)
                        except OSError as e:
                            issues_list = cast(list[dict[str, Any]], results["issues"])
                            issues_list.append(
                                {
                                    "message": "Broken symlink encountered",
                                    "severity": IssueSeverity.WARNING.value,
                                    "location": file_path,
                                    "details": {"error": str(e)},
                                }
                            )
                            continue

                        # Resolve the relative link target
                        resolved_target = (Path(file_path).parent / link_target).resolve()
                        # Check if target is in the blobs directory of the same model cache
                        if "/blobs/" in str(resolved_target):
                            # Extract the model cache root (e.g., models--distilbert-base-uncased)
                            cache_parts = str(base_dir).split("/")
                            for i, part in enumerate(cache_parts):
                                if part.startswith("models--") and i > 0:
                                    cache_root = "/".join(cache_parts[: i + 1])
                                    # Check if the target is within the same model's cache structure
                                    if str(resolved_target).startswith(cache_root):
                                        is_hf_cache_symlink = True
                                        # Update the resolved_file to the actual target for scanning
                                        resolved_file = resolved_target
                                    break

                    if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(resolved_file)):
                        issues_list = cast(list[dict[str, Any]], results["issues"])
                        issues_list.append(
                            {
                                "message": "Path traversal outside scanned directory",
                                "severity": IssueSeverity.CRITICAL.value,
                                "location": file_path,
                                "details": {"resolved_path": str(resolved_file)},
                            },
                        )
                        continue

                    # Skip non-model files early if filtering is enabled
                    skip_file_types = config.get("skip_file_types", True)
                    if skip_file_types and should_skip_file(file_path):
                        filename_lower = Path(file_path).name.lower()
                        if filename_lower in LICENSE_FILES:
                            file_meta = cast(dict[str, Any], results["file_metadata"])
                            try:
                                license_metadata = collect_license_metadata(str(resolved_file))
                                file_meta[str(resolved_file)] = license_metadata
                                logger.debug(f"Collected license metadata from skipped file: {file_path}")
                            except Exception as e:
                                logger.warning(f"Error collecting license metadata for {file_path}: {e}")
                        else:
                            logger.debug(f"Skipping non-model file: {file_path}")
                        continue

                    # Handle DVC files and get target paths
                    target_paths = [resolved_file]
                    if file.endswith(".dvc"):
                        dvc_targets = resolve_dvc_file(file_path)
                        if dvc_targets:
                            target_paths = [Path(t).resolve() for t in dvc_targets]

                    for target_path in target_paths:
                        target_str = str(target_path)
                        if target_str in scanned_paths:
                            continue
                        scanned_paths.add(target_str)

                        if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(target_path)):
                            issues_list.append(
                                {
                                    "message": "Path traversal outside scanned directory",
                                    "severity": IssueSeverity.CRITICAL.value,
                                    "location": str(target_path),
                                    "details": {"resolved_path": str(target_path)},
                                },
                            )
                            continue

                        # Add to files to scan list instead of scanning immediately
                        files_to_scan.append(target_str)

            # Second pass: group files by content and scan unique content only once
            if files_to_scan:
                content_groups = _group_files_by_content(files_to_scan)
                content_processed = 0

                for content_hash, file_paths in content_groups.items():
                    if limit_reached:
                        break

                    # Scan the first file in each content group (representative)
                    representative_file = file_paths[0]

                    # Check for interrupts
                    check_interrupted()

                    # Check timeout
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Scan timeout after {timeout} seconds")

                    # Update progress
                    if progress_callback:
                        if total_files is not None and total_files > 0:
                            progress_callback(
                                f"Scanning file {processed_files + 1}/{total_files}: "
                                f"{Path(representative_file).name} ({len(file_paths)} copies)",
                                processed_files / total_files * 100,
                            )
                        else:
                            progress_callback(
                                f"Scanning file {processed_files + 1}: "
                                f"{Path(representative_file).name} ({len(file_paths)} copies)",
                                0.0,
                            )

                    try:
                        # Check for interrupts before scanning each file
                        check_interrupted()

                        file_result = scan_file(representative_file, config)
                        results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + file_result.bytes_scanned
                        results["files_scanned"] = cast(int, results["files_scanned"]) + len(
                            file_paths
                        )  # Count all copies
                        processed_files += len(file_paths)  # Count all copies for progress
                        content_processed += 1

                        scanner_name = file_result.scanner_name
                        scanners_list = cast(list[str], results["scanners"])
                        if scanner_name and scanner_name not in scanners_list:
                            scanners_list.append(scanner_name)

                        issues_list = cast(list[dict[str, Any]], results["issues"])

                        # Add issues for each file path that shares this content
                        for issue in file_result.issues:
                            issue_dict = issue.to_dict()
                            # Update location to include all file paths with this content
                            if len(file_paths) > 1:
                                all_locations = " ".join(file_paths)
                                issue_dict["location"] = all_locations
                                # Add details about duplicate files
                                if "details" not in issue_dict:
                                    issue_dict["details"] = {}
                                issue_dict["details"]["duplicate_files"] = file_paths
                                issue_dict["details"]["content_hash"] = content_hash
                            issues_list.append(issue_dict)

                        # Add checks for each file path that shares this content
                        if hasattr(file_result, "checks"):
                            checks_list = cast(list[dict[str, Any]], results["checks"])
                            for check in file_result.checks:
                                check_dict = check.to_dict()
                                # Update location to include all file paths with this content
                                if len(file_paths) > 1:
                                    # For checks, we want to show all file locations affected
                                    check_dict["location"] = " ".join(file_paths)
                                    # Add details about duplicate files
                                    if "details" not in check_dict:
                                        check_dict["details"] = {}
                                    check_dict["details"]["duplicate_files"] = file_paths
                                    check_dict["details"]["content_hash"] = content_hash
                                checks_list.append(check_dict)

                        # Add assets for all file paths that share this content
                        for file_path in file_paths:
                            _add_asset_to_results(results, file_path, file_result)

                            # Add metadata for all file paths
                            file_meta = cast(dict[str, Any], results["file_metadata"])
                            license_metadata = collect_license_metadata(file_path)
                            combined_metadata = {**file_result.metadata, **license_metadata}
                            # Add information about content deduplication
                            combined_metadata["content_hash"] = content_hash
                            combined_metadata["duplicate_files"] = file_paths if len(file_paths) > 1 else None
                            file_meta[file_path] = combined_metadata

                        if max_total_size > 0 and cast(int, results["bytes_scanned"]) > max_total_size:
                            issues_list.append(
                                {
                                    "message": (
                                        f"Total scan size limit exceeded: {results['bytes_scanned']} bytes "
                                        f"(max: {max_total_size})"
                                    ),
                                    "severity": IssueSeverity.WARNING.value,
                                    "location": representative_file,
                                    "details": {"max_total_size": max_total_size},
                                }
                            )
                            limit_reached = True
                            break
                    except Exception as e:
                        logger.warning(f"Error scanning file {representative_file}: {e!s}")
                        results["success"] = False
                        issues_list = cast(list[dict[str, Any]], results["issues"])

                        # Add error for all files that share this content
                        for file_path in file_paths:
                            issues_list.append(
                                {
                                    "message": f"Error scanning file: {e!s}",
                                    "severity": IssueSeverity.CRITICAL.value,
                                    "location": file_path,
                                    "details": {"exception_type": type(e).__name__},
                                }
                            )
                            _add_error_asset_to_results(results, file_path)

                # This section is now handled by the content grouping logic above
                pass

            # Final progress update for directory scan
            if progress_callback and not limit_reached and total_files is not None and total_files > 0:
                progress_callback(
                    f"Completed scanning {processed_files} files",
                    100.0,
                )
            # Stop scanning if size limit reached
            if limit_reached:
                logger.info("Scan terminated early due to total size limit")
                issues_list = cast(list[dict[str, Any]], results["issues"])
                issues_list.append(
                    {
                        "message": "Scan terminated early due to total size limit",
                        "severity": IssueSeverity.INFO.value,
                        "location": path,
                        "details": {"max_total_size": max_total_size},
                    }
                )
        else:
            # Scan a single file or DVC pointer
            target_files = [path]
            if path.endswith(".dvc"):
                dvc_targets = resolve_dvc_file(path)
                if dvc_targets:
                    target_files = dvc_targets

            for _idx, target in enumerate(target_files):
                # Check for interrupts
                check_interrupted()

                if progress_callback:
                    progress_callback(f"Scanning file: {target}", 0.0)

                file_size = os.path.getsize(target)
                results["files_scanned"] = cast(int, results.get("files_scanned", 0)) + 1

                if progress_callback is not None and file_size > 0:

                    def create_progress_open(callback: Callable[[str, float], None], current_file_size: int):
                        """Create a progress-aware file opener with properly bound variables."""

                        def progress_open(file_path: str, mode: str = "r", *args: Any, **kwargs: Any) -> IO[Any]:
                            # Note: We intentionally don't use a context manager here because we need to
                            # return the file object for further processing. The SIM115 warning is
                            # suppressed because this is a legitimate use case.
                            file = builtins.open(file_path, mode, *args, **kwargs)  # noqa: SIM115
                            file_pos = 0

                            original_read = file.read

                            def progress_read(size: int = -1) -> Any:
                                nonlocal file_pos
                                data = original_read(size)
                                if isinstance(data, (str, bytes)):
                                    file_pos += len(data)
                                callback(
                                    f"Reading file: {os.path.basename(file_path)}",
                                    min(file_pos / current_file_size * 100, 100),
                                )
                                return data

                            file.read = progress_read  # type: ignore[method-assign]
                            return file

                        return progress_open

                    progress_opener = create_progress_open(progress_callback, file_size)
                    with _OPEN_PATCH_LOCK, patch("builtins.open", progress_opener):
                        file_result = scan_file(target, config)
                else:
                    file_result = scan_file(target, config)

                results["bytes_scanned"] = cast(int, results["bytes_scanned"]) + file_result.bytes_scanned

                scanner_name = file_result.scanner_name
                scanners_list = cast(list[str], results["scanners"])
                if scanner_name and scanner_name not in scanners_list:
                    scanners_list.append(scanner_name)

                issues_list = cast(list[dict[str, Any]], results["issues"])
                for issue in file_result.issues:
                    issues_list.append(issue.to_dict())

                # Add checks if available
                if hasattr(file_result, "checks"):
                    checks_list = cast(list[dict[str, Any]], results["checks"])
                    for check in file_result.checks:
                        checks_list.append(check.to_dict())

                _add_asset_to_results(results, target, file_result)

                file_meta = cast(dict[str, Any], results["file_metadata"])
                license_metadata = collect_license_metadata(target)
                combined_metadata = {**file_result.metadata, **license_metadata}
                file_meta[target] = combined_metadata

                if max_total_size > 0 and cast(int, results["bytes_scanned"]) > max_total_size:
                    issues_list.append(
                        {
                            "message": (
                                f"Total scan size limit exceeded: {results['bytes_scanned']} bytes "
                                f"(max: {max_total_size})"
                            ),
                            "severity": IssueSeverity.WARNING.value,
                            "location": target,
                            "details": {"max_total_size": max_total_size},
                        }
                    )

                if progress_callback:
                    progress_callback(f"Completed scanning: {target}", 100.0)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        results["success"] = False
        issue_dict = {
            "message": "Scan interrupted by user",
            "severity": IssueSeverity.INFO.value,
            "details": {"interrupted": True},
        }
        issues_list = cast(list[dict[str, Any]], results["issues"])
        issues_list.append(issue_dict)
    except Exception as e:
        logger.exception(f"Error during scan: {e!s}")
        results["success"] = False
        issue_dict = {
            "message": f"Error during scan: {e!s}",
            "severity": IssueSeverity.CRITICAL.value,
            "details": {"exception_type": type(e).__name__},
        }
        issues_list = cast(list[dict[str, Any]], results["issues"])
        issues_list.append(issue_dict)
        _add_error_asset_to_results(results, path)

    # Add final timing information
    results["finish_time"] = time.time()
    results["duration"] = cast(float, results["finish_time"]) - cast(
        float,
        results["start_time"],
    )

    # Consolidate checks for cleaner reporting
    try:
        _consolidate_checks(results)
    except Exception as e:
        logger.warning(f"Error consolidating checks: {e!s}")

    # Add license warnings if any
    try:
        license_warnings = check_commercial_use_warnings(results, strict=config.get("strict_license", False))
        issues_list = cast(list[dict[str, Any]], results["issues"])
        for warning in license_warnings:
            # Convert license warnings to issues
            issue_dict = {
                "message": warning["message"],
                "severity": warning["severity"],
                "location": "",  # License warnings are generally project-wide
                "details": warning.get("details", {}),
                "type": warning["type"],
            }
            issues_list.append(issue_dict)
    except Exception as e:
        logger.warning(f"Error checking license warnings: {e!s}")

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
            any(indicator in issue.get("message", "") for indicator in operational_error_indicators)
            for issue in issues_list
            if isinstance(issue, dict)
            and issue.get("severity") in {IssueSeverity.WARNING.value, IssueSeverity.CRITICAL.value}
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
    - 2: Operational errors occurred during scanning or no files scanned

    Args:
        results: Dictionary with scan results

    Returns:
        Exit code (0, 1, or 2)
    """
    # Check for operational errors first (highest priority)
    if results.get("has_errors", False):
        return 2

    # Check if no files were scanned
    files_scanned = results.get("files_scanned", 0)
    if files_scanned == 0:
        return 2

    # Check for any security findings (warnings, errors, or critical issues)
    issues = results.get("issues", [])
    if issues:
        # Filter out DEBUG and INFO level issues for exit code determination
        # Only WARNING, ERROR (legacy), and CRITICAL issues should trigger exit code 1
        security_issues = [
            issue
            for issue in issues
            if isinstance(issue, dict) and issue.get("severity") in ["warning", "error", "critical"]
        ]
        if security_issues:
            return 1

    # No issues found
    return 0


# _should_skip_file has been moved to utils.file_filter module


def _is_huggingface_cache_file(path: str) -> bool:
    """
    Check if a file is a HuggingFace cache/metadata file that should be skipped.

    Args:
        path: File path to check

    Returns:
        True if the file is a HuggingFace cache file that should be skipped
    """
    import os

    filename = os.path.basename(path)

    # HuggingFace cache file patterns - be more specific
    hf_cache_patterns = [
        ".lock",  # Download lock files
        ".metadata",  # HuggingFace metadata files
    ]

    # Check if file ends with cache patterns
    for pattern in hf_cache_patterns:
        if filename.endswith(pattern):
            return True

    # Check for specific HuggingFace cache metadata files
    # We no longer skip all HuggingFace cache files since we handle symlinks properly now

    # Check for Git-related files that are commonly cached
    if filename in [".gitignore", ".gitattributes", "main", "HEAD"]:
        return True

    # Check if file is in refs directory (Git references, not actual model files)
    return bool("/refs/" in path and filename in ["main", "HEAD"])


def scan_file(path: str, config: Optional[dict[str, Any]] = None) -> ScanResult:
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
    validate_scan_config(config)

    # Skip HuggingFace cache files to reduce noise
    if _is_huggingface_cache_file(path):
        sr = ScanResult(scanner_name="skipped")
        sr.add_issue(
            "Skipped HuggingFace cache file",
            severity=IssueSeverity.DEBUG,
            details={"path": path, "reason": "huggingface_cache_file"},
        )
        sr.finish(success=True)
        return sr

    # Get file size for later checks
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        sr = ScanResult(scanner_name="error")
        sr.add_issue(
            f"Error checking file size: {e}",
            severity=IssueSeverity.WARNING,
            details={"error": str(e), "path": path},
        )
        sr.finish(success=False)
        return sr

    # Check if we should use extreme handler BEFORE applying size limits
    # Extreme handler bypasses size limits for large models
    use_extreme_handler = should_use_advanced_handler(path)

    # Check file size limit only if NOT using extreme handler
    max_file_size = config.get("max_file_size", 0)  # Default unlimited
    if not use_extreme_handler and max_file_size > 0 and file_size > max_file_size:
        sr = ScanResult(scanner_name="size_check")
        sr.add_issue(
            f"File too large to scan: {file_size} bytes (max: {max_file_size})",
            severity=IssueSeverity.WARNING,
            details={
                "file_size": file_size,
                "max_file_size": max_file_size,
                "path": path,
                "hint": "Consider using extreme large model support for files over 50GB",
            },
        )
        sr.finish(success=False)
        return sr

    logger.debug(f"Processing: {path}")

    header_format = detect_file_format(path)
    ext_format = detect_format_from_extension(path)
    ext = os.path.splitext(path)[1].lower()

    # Validate file type consistency as a security check
    file_type_valid = validate_file_type(path)
    discrepancy_msg = None
    magic_format = None

    if not file_type_valid:
        # File type validation failed - this is a security concern
        # Get the actual magic bytes format for accurate error message
        magic_format = detect_file_format_from_magic(path)
        discrepancy_msg = (
            f"File type validation failed: extension indicates {ext_format} but magic bytes "
            f"indicate {magic_format}. This could indicate file spoofing or corruption."
        )
        logger.warning(discrepancy_msg)
    elif header_format != ext_format and header_format != "unknown" and ext_format != "unknown":
        # Don't warn about common PyTorch .bin files that are ZIP or pickle format internally
        # This is expected behavior for torch.save() and HuggingFace models
        if not (
            (ext_format == "pytorch_binary" and header_format in ["zip", "pickle"] and ext == ".bin")
            or (ext_format == "pytorch_binary" and header_format == "pickle" and ext in [".pt", ".pth"])
        ):
            discrepancy_msg = f"File extension indicates {ext_format} but header indicates {header_format}."
            logger.warning(discrepancy_msg)

    # Prefer scanner based on header format using lazy loading
    preferred_scanner: Optional[type[BaseScanner]] = None

    # Special handling for PyTorch files that are ZIP-based
    if header_format == "zip" and ext in [".pt", ".pth"]:
        preferred_scanner = _registry.load_scanner_by_id("pytorch_zip")
    elif header_format == "zip" and ext == ".bin":
        # PyTorch .bin files saved with torch.save() are ZIP format internally
        # Use PickleScanner which can handle both pickle and ZIP-based PyTorch files
        preferred_scanner = _registry.load_scanner_by_id("pickle")
    else:
        format_to_scanner = {
            "pickle": "pickle",
            "pytorch_binary": "pytorch_binary",
            "hdf5": "keras_h5",
            "safetensors": "safetensors",
            "tensorflow_directory": "tf_savedmodel",
            "protobuf": "tf_savedmodel",
            "zip": "zip",
            "onnx": "onnx",
            "gguf": "gguf",
            "ggml": "gguf",
            "numpy": "numpy",
        }
        scanner_id = format_to_scanner.get(header_format)
        if scanner_id:
            preferred_scanner = _registry.load_scanner_by_id(scanner_id)

    result: Optional[ScanResult]

    # We already checked use_extreme_handler above for size limit bypass
    # Now check if we should use regular large handler
    use_large_handler = should_use_large_file_handler(path) and not use_extreme_handler
    progress_callback = config.get("progress_callback")
    timeout = config.get("timeout", 1800)

    if preferred_scanner and preferred_scanner.can_handle(path):
        logger.debug(
            f"Using {preferred_scanner.name} scanner for {path} based on header",
        )
        scanner = preferred_scanner(config=config)

        try:
            if use_extreme_handler:
                logger.debug(f"Large file optimization enabled: {path}")
                result = scan_advanced_large_file(
                    path, scanner, progress_callback, timeout * 2
                )  # Double timeout for extreme files
            elif use_large_handler:
                logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                result = scan_large_file(path, scanner, progress_callback, timeout)
            else:
                result = scanner.scan(path)
        except TimeoutError as e:
            # Handle timeout gracefully
            result = ScanResult(scanner_name=preferred_scanner.name)
            result.add_issue(
                f"Scan timeout: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"timeout": config.get("timeout", 300), "error": str(e)},
            )
            result.finish(success=False)
    else:
        # Use registry's lazy loading method to avoid loading all scanners
        scanner_class = _registry.get_scanner_for_path(path)
        if scanner_class:
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)

            try:
                if use_extreme_handler:
                    logger.debug(f"Large file optimization enabled: {path}")
                    result = scan_advanced_large_file(
                        path, scanner, progress_callback, timeout * 2
                    )  # Double timeout for extreme files
                elif use_large_handler:
                    logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                    result = scan_large_file(path, scanner, progress_callback, timeout)
                else:
                    result = scanner.scan(path)
            except TimeoutError as e:
                # Handle timeout gracefully
                result = ScanResult(scanner_name=scanner_class.name)
                result.add_issue(
                    f"Scan timeout: {e}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"timeout": config.get("timeout", 300), "error": str(e)},
                )
                result.finish(success=False)
        else:
            format_ = header_format
            sr = ScanResult(scanner_name="unknown")
            sr.add_issue(
                f"Unknown or unhandled format: {format_}",
                severity=IssueSeverity.DEBUG,
                details={"format": format_, "path": path},
            )
            result = sr

    if discrepancy_msg:
        # Determine severity based on whether it's a validation failure or just a discrepancy
        severity = IssueSeverity.WARNING if not file_type_valid else IssueSeverity.DEBUG
        # For validation failures, use the actual magic format
        detail_header_format = magic_format if not file_type_valid else header_format
        result.add_issue(
            discrepancy_msg + " Using header-based detection.",
            severity=severity,
            location=path,
            details={
                "extension_format": ext_format,
                "header_format": detail_header_format,
                "file_type_validation_failed": not file_type_valid,
            },
        )

    return result


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
    scan_dict = scan_result.to_dict() if isinstance(scan_result, ScanResult) else scan_result

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
