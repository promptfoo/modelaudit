import builtins
import hashlib
import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import IO, Any, Callable, Optional, Union
from unittest.mock import patch

from modelaudit.interrupt_handler import check_interrupted
from modelaudit.license_checker import (
    LICENSE_FILES,
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.models import ModelAuditResultModel, ScanConfigModel, create_initial_audit_result
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
    results: ModelAuditResultModel,
    file_path: str,
    file_result: ScanResult,
) -> None:
    """Helper function to add an asset entry to the results."""
    from .models import AssetModel

    asset_dict = asset_from_scan_result(file_path, file_result)
    asset = AssetModel(**asset_dict)
    results.assets.append(asset)


def _add_error_asset_to_results(results: ModelAuditResultModel, file_path: str) -> None:
    """Helper function to add an error asset entry to the results."""
    from .models import AssetModel

    asset = AssetModel(path=file_path, type="error", size=None, tensors=None, keys=None, contents=None)
    results.assets.append(asset)


def _add_scan_result_to_model(
    results: ModelAuditResultModel, scan_metadata: dict[str, Any], file_result: ScanResult, file_path: str
) -> None:
    """Helper function to add scan result data to Pydantic model."""

    from .models import FileMetadataModel
    from .scanners.base import Check, Issue

    # Update byte counts
    results.bytes_scanned += file_result.bytes_scanned
    # files_scanned is incremented elsewhere to avoid double counting

    # Add scanner to tracking lists
    if file_result.scanner_name and file_result.scanner_name not in scan_metadata.get("scanners", []):
        scan_metadata.setdefault("scanners", []).append(file_result.scanner_name)
    if (
        file_result.scanner_name
        and file_result.scanner_name not in results.scanner_names
        and file_result.scanner_name != "unknown"
    ):
        results.scanner_names.append(file_result.scanner_name)

    # Convert and add issues
    for issue in file_result.issues:
        issue_dict = issue.to_dict() if hasattr(issue, "to_dict") else issue
        if isinstance(issue_dict, dict):
            results.issues.append(Issue(**issue_dict))

    # Convert and add checks
    for check in file_result.checks:
        check_dict = check.to_dict() if hasattr(check, "to_dict") else check
        if isinstance(check_dict, dict):
            results.checks.append(Check(**check_dict))

    # Add file metadata if available
    if hasattr(file_result, "metadata") and file_result.metadata:
        # Convert ml_context if present
        metadata_dict = file_result.metadata.copy()
        if "ml_context" in metadata_dict and isinstance(metadata_dict["ml_context"], dict):
            from .models import MLContextModel

            metadata_dict["ml_context"] = MLContextModel(**metadata_dict["ml_context"])
        results.file_metadata[file_path] = FileMetadataModel(**metadata_dict)


def _add_issue_to_model(
    results: ModelAuditResultModel,
    message: str,
    severity: str = "warning",
    location: Optional[str] = None,
    details: Optional[dict] = None,
    issue_type: Optional[str] = None,
) -> None:
    """Helper function to add an issue directly to the Pydantic model."""
    import time

    from .scanners.base import Issue, IssueSeverity

    # Convert string severity to enum
    severity_enum = {
        "debug": IssueSeverity.DEBUG,
        "info": IssueSeverity.INFO,
        "warning": IssueSeverity.WARNING,
        "critical": IssueSeverity.CRITICAL,
    }.get(severity.lower(), IssueSeverity.WARNING)

    issue = Issue(
        message=message,
        severity=severity_enum,
        location=location,
        details=details or {},
        timestamp=time.time(),
        why=None,
        type=issue_type,
    )
    results.issues.append(issue)


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


def _extract_primary_asset_from_location(location: str) -> str:
    """Extract primary asset path from location string.

    Args:
        location: Location string in various formats

    Returns:
        Primary asset path, or "unknown" if cannot be determined
    """
    if not location or not isinstance(location, str):
        return "unknown"

    # Split on spaces first to handle duplicate file listings
    locations = location.strip().split()
    if not locations:
        return "unknown"

    primary_location = locations[0]
    # Extract main file path (before any ':' separator for archive contents)
    drive, tail = os.path.splitdrive(primary_location)
    if ":" in tail:
        tail = tail.split(":", 1)[0]
    primary_asset = f"{drive}{tail}"

    # Normalize empty paths
    return primary_asset.strip() if primary_asset.strip() else "unknown"


def _group_checks_by_asset(checks_list: list[Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Group checks by (check_name, primary_asset_path).

    Args:
        checks_list: List of check dictionaries

    Returns:
        Dictionary mapping (check_name, asset_path) to list of checks
    """
    check_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for i, check in enumerate(checks_list):
        # Type guard: ensure check is a dictionary
        if not isinstance(check, dict):
            logger.warning(f"Invalid check format at index {i}, skipping: {type(check)}")
            continue

        check_name = check.get("name", "Unknown Check")
        location = check.get("location", "")
        primary_asset = _extract_primary_asset_from_location(location)

        group_key = (check_name, primary_asset)
        check_groups[group_key].append(check)

    return check_groups


def _create_consolidated_message(
    check_name: str, group_checks: list[dict[str, Any]], consolidated_status: str, failed_count: int
) -> str:
    """Create appropriate consolidated message based on check results.

    Args:
        check_name: Name of the check
        group_checks: List of checks in this group
        consolidated_status: Overall status (passed/failed)
        failed_count: Number of failed checks

    Returns:
        Consolidated message string
    """
    if consolidated_status == "passed":
        # For passed checks, use the message from first check or create generic
        messages = {c.get("message", "") for c in group_checks if c.get("status") == "passed"}

        # If all passed checks have the same message, use it
        if len(messages) == 1:
            return str(next(iter(messages)))
        else:
            return f"{check_name} completed successfully"

    else:  # failed status
        # For failed checks, summarize or use common message
        failed_messages = {c.get("message", "") for c in group_checks if c.get("status") == "failed"}

        if len(failed_messages) == 1:
            return str(next(iter(failed_messages)))
        elif failed_count == 1:
            return f"{check_name} found 1 issue"
        else:
            return f"{check_name} found {failed_count} issues"


def _collect_consolidated_details(group_checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect and consolidate details from failed checks.

    Args:
        group_checks: List of checks in this group

    Returns:
        Consolidated details dictionary
    """
    consolidated_details: dict[str, Any] = {"component_count": len(group_checks)}
    failed_details: list[Any] = []

    for check in group_checks:
        if check.get("status") == "failed" and check.get("details"):
            failed_details.append(check["details"])

    if failed_details:
        consolidated_details["findings"] = failed_details

    return consolidated_details


def _extract_failure_context(group_checks: list[dict[str, Any]]) -> tuple[Optional[str], Optional[str]]:
    """Extract severity and explanation from failed checks.

    Args:
        group_checks: List of checks in this group

    Returns:
        Tuple of (severity, explanation) from failed checks
    """
    consolidated_severity = None
    consolidated_why = None

    for check in group_checks:
        if check.get("status") == "failed":
            if not consolidated_severity and check.get("severity"):
                consolidated_severity = check["severity"]
            if not consolidated_why and check.get("why"):
                consolidated_why = check["why"]

            # Stop once we have both
            if consolidated_severity and consolidated_why:
                break

    return consolidated_severity, consolidated_why


def _get_consolidated_timestamp(group_checks: list[dict[str, Any]]) -> float:
    """Get the most recent timestamp from a group of checks.

    Args:
        group_checks: List of checks in this group

    Returns:
        Most recent timestamp, or current time if none found
    """
    timestamps = [c.get("timestamp", 0) for c in group_checks if isinstance(c.get("timestamp"), (int, float))]
    return max(timestamps) if timestamps else time.time()


def _update_result_counts(
    results: ModelAuditResultModel, consolidated_checks: list[dict[str, Any]], original_count: int
) -> None:
    """Update result model with consolidated check counts.

    Args:
        results: Results model to update
        consolidated_checks: List of consolidated checks
        original_count: Original number of checks before consolidation
    """
    total_checks = len(consolidated_checks)
    passed_checks = sum(1 for c in consolidated_checks if c.get("status") == "passed")
    failed_checks = sum(1 for c in consolidated_checks if c.get("status") == "failed")
    skipped_checks = total_checks - passed_checks - failed_checks

    # Validate counts make sense
    if passed_checks + failed_checks + skipped_checks != total_checks:
        logger.warning(
            f"Check count mismatch: {passed_checks}P + {failed_checks}F + {skipped_checks}S != {total_checks}T"
        )

    results.total_checks = total_checks
    results.passed_checks = passed_checks
    results.failed_checks = failed_checks

    # Log consolidation summary
    reduction_count = original_count - total_checks
    logger.info(f"Check consolidation: {original_count} -> {total_checks} ({reduction_count} duplicates removed)")

    if skipped_checks > 0:
        logger.debug(f"Check status distribution: {passed_checks}P, {failed_checks}F, {skipped_checks}S")


def _consolidate_checks(results: ModelAuditResultModel) -> None:
    """Consolidate duplicate checks by name and asset for cleaner reporting.

    Groups checks by (check_name, primary_asset_path) and consolidates them into
    single checks per asset. This provides a cleaner reporting view while preserving
    all findings from thorough scanning.

    Args:
        results: Scan results dictionary containing 'checks' list

    Raises:
        Exception: Logs errors but doesn't fail the scan if consolidation fails
    """
    checks_list = [check.model_dump() if hasattr(check, "model_dump") else check for check in results.checks]
    if not checks_list:
        logger.debug("No checks to consolidate")
        return

    logger.debug(f"Starting consolidation of {len(checks_list)} checks")

    # Group checks by (check_name, primary_asset_path)
    check_groups = _group_checks_by_asset(checks_list)

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
        consolidated_status = "failed" if failed_count > 0 else "passed"

        # Build consolidated check
        consolidated_check = {
            "name": check_name,
            "status": consolidated_status,
            "message": _create_consolidated_message(check_name, group_checks, consolidated_status, failed_count),
            "location": group_checks[0].get("location", primary_asset),
            "details": _collect_consolidated_details(group_checks),
            "timestamp": _get_consolidated_timestamp(group_checks),
        }

        # Add optional fields for failed checks
        consolidated_severity, consolidated_why = _extract_failure_context(group_checks)
        if consolidated_severity:
            consolidated_check["severity"] = consolidated_severity
        if consolidated_why:
            consolidated_check["why"] = consolidated_why

        consolidated_checks.append(consolidated_check)

        # Log consolidation info
        logger.debug(
            f"Consolidated {len(group_checks)} '{check_name}' checks for {primary_asset} "
            f"({passed_count} passed, {failed_count} failed)"
        )

    # Update results with consolidated checks and counts - convert to Pydantic models
    from .models import Check

    results.checks = [Check(**check) if isinstance(check, dict) else check for check in consolidated_checks]
    _update_result_counts(results, consolidated_checks, len(checks_list))


def validate_scan_config(config: dict[str, Any]) -> ScanConfigModel:
    """Validate configuration parameters for scanning using Pydantic model."""
    try:
        return ScanConfigModel.from_dict(config)
    except Exception as e:
        raise ValueError(f"Invalid scan configuration: {e}") from e


def create_scan_config(**kwargs: Any) -> ScanConfigModel:
    """Create a validated scan configuration from keyword arguments."""
    return ScanConfigModel(**kwargs)


def scan_model_directory_or_file(
    path: str,
    blacklist_patterns: Optional[list[str]] = None,
    timeout: int = 3600,  # 1 hour for large models (up to 8GB+)
    max_file_size: int = 0,  # 0 means unlimited - support any size
    max_total_size: int = 0,  # 0 means unlimited
    strict_license: bool = False,
    progress_callback: Optional[Callable[[str, float], None]] = None,
    skip_file_types: bool = True,
    **kwargs,
) -> ModelAuditResultModel:
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
        ModelAuditResultModel with scan results
    """
    # Start timer for timeout
    start_time = time.time()

    # Initialize results using Pydantic model from the start
    results = create_initial_audit_result()
    # Store additional scan metadata
    scan_metadata = {
        "path": path,
        "success": True,
        "scanners": [],  # Track the scanners used (different from scanner_names)
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

    # Check if metadata scanner is available once (optimization - avoids loading scanner)
    metadata_scanner_available = _registry.has_scanner_class("MetadataScanner")

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
                    # Use helper function to add scan result to Pydantic model
                    _add_scan_result_to_model(results, scan_metadata, scan_result, stream_url)

                    # Add asset
                    _add_asset_to_results(results, stream_url, scan_result)

                    if not was_complete:
                        _add_issue_to_model(
                            results,
                            "Streaming analysis was partial - only analyzed file header",
                            severity=IssueSeverity.INFO.value,
                            location=stream_url,
                            details={"analysis_complete": False},
                        )
                else:
                    raise ValueError(f"Streaming analysis failed for {stream_url}")
            else:
                raise ValueError(f"No scanner available for {stream_url}")

            # Return early for streaming - finalize the model
            results.finalize_statistics()
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
                            _add_issue_to_model(
                                results,
                                "Broken symlink encountered",
                                severity=IssueSeverity.WARNING.value,
                                location=file_path,
                                details={"error": str(e)},
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
                        _add_issue_to_model(
                            results,
                            "Path traversal outside scanned directory",
                            severity=IssueSeverity.CRITICAL.value,
                            location=file_path,
                            details={"resolved_path": str(resolved_file)},
                        )
                        continue

                    # Skip non-model files early if filtering is enabled
                    skip_file_types = config.get("skip_file_types", True)
                    if skip_file_types and should_skip_file(
                        file_path, metadata_scanner_available=metadata_scanner_available
                    ):
                        filename_lower = Path(file_path).name.lower()
                        if filename_lower in LICENSE_FILES:
                            try:
                                license_metadata = collect_license_metadata(str(resolved_file))
                                from .models import FileMetadataModel

                                results.file_metadata[str(resolved_file)] = FileMetadataModel(**license_metadata)
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
                            _add_issue_to_model(
                                results,
                                "Path traversal outside scanned directory",
                                severity=IssueSeverity.CRITICAL.value,
                                location=str(target_path),
                                details={"resolved_path": str(target_path)},
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
                        results.bytes_scanned += file_result.bytes_scanned
                        results.files_scanned += len(file_paths)  # Count all copies
                        processed_files += len(file_paths)  # Count all copies for progress
                        content_processed += 1

                        # Add scanner to tracking list (different from scanner_names)
                        scanner_name = file_result.scanner_name
                        if scanner_name:
                            # Ensure scanners list exists and is properly typed
                            if "scanners" not in scan_metadata:
                                scan_metadata["scanners"] = []
                            scanners_list = scan_metadata["scanners"]
                            if isinstance(scanners_list, list) and scanner_name not in scanners_list:
                                scanners_list.append(scanner_name)
                        if scanner_name and scanner_name not in results.scanner_names and scanner_name != "unknown":
                            results.scanner_names.append(scanner_name)

                        # Add issues for each file path that shares this content using Pydantic models
                        from .scanners.base import Issue

                        for issue in file_result.issues:
                            issue_dict = issue.to_dict() if hasattr(issue, "to_dict") else issue
                            if isinstance(issue_dict, dict):
                                # Update location to include all file paths with this content
                                if len(file_paths) > 1:
                                    all_locations = " ".join(file_paths)
                                    issue_dict["location"] = all_locations
                                    # Add details about duplicate files
                                    if "details" not in issue_dict:
                                        issue_dict["details"] = {}
                                    issue_dict["details"]["duplicate_files"] = file_paths
                                    issue_dict["details"]["content_hash"] = content_hash

                                # Ensure timestamp is present
                                if "timestamp" not in issue_dict:
                                    issue_dict["timestamp"] = time.time()

                                results.issues.append(Issue(**issue_dict))

                        # Add checks for each file path that shares this content using Pydantic models
                        if hasattr(file_result, "checks"):
                            from .models import Check

                            for check in file_result.checks:
                                check_dict = check.to_dict() if hasattr(check, "to_dict") else check
                                if isinstance(check_dict, dict):
                                    # Update location to include all file paths with this content
                                    if len(file_paths) > 1:
                                        # For checks, we want to show all file locations affected
                                        check_dict["location"] = " ".join(file_paths)
                                        # Add details about duplicate files
                                        if "details" not in check_dict:
                                            check_dict["details"] = {}
                                        check_dict["details"]["duplicate_files"] = file_paths
                                        check_dict["details"]["content_hash"] = content_hash

                                    # Ensure timestamp is present
                                    if "timestamp" not in check_dict:
                                        check_dict["timestamp"] = time.time()

                                    results.checks.append(Check(**check_dict))

                        # Add assets for all file paths that share this content
                        for file_path in file_paths:
                            _add_asset_to_results(results, file_path, file_result)

                            # Add metadata for all file paths using Pydantic models
                            license_metadata = collect_license_metadata(file_path)
                            combined_metadata = {**file_result.metadata, **license_metadata}
                            # Add information about content deduplication
                            combined_metadata["content_hash"] = content_hash
                            combined_metadata["duplicate_files"] = file_paths if len(file_paths) > 1 else None

                            # Convert ml_context if present
                            if "ml_context" in combined_metadata and isinstance(combined_metadata["ml_context"], dict):
                                from .models import MLContextModel

                                combined_metadata["ml_context"] = MLContextModel(**combined_metadata["ml_context"])

                            from .models import FileMetadataModel

                            results.file_metadata[file_path] = FileMetadataModel(**combined_metadata)

                        if max_total_size > 0 and results.bytes_scanned > max_total_size:
                            _add_issue_to_model(
                                results,
                                f"Total scan size limit exceeded: {results.bytes_scanned} bytes "
                                f"(max: {max_total_size})",
                                severity=IssueSeverity.WARNING.value,
                                location=representative_file,
                                details={"max_total_size": max_total_size},
                            )
                            limit_reached = True
                            break
                    except Exception as e:
                        logger.warning(f"Error scanning file {representative_file}: {e!s}")
                        scan_metadata["success"] = False

                        # Add error for all files that share this content
                        for file_path in file_paths:
                            _add_issue_to_model(
                                results,
                                f"Error scanning file: {e!s}",
                                severity=IssueSeverity.CRITICAL.value,
                                location=file_path,
                                details={"exception_type": type(e).__name__},
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
                _add_issue_to_model(
                    results,
                    "Scan terminated early due to total size limit",
                    severity=IssueSeverity.INFO.value,
                    location=path,
                    details={"max_total_size": max_total_size},
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
                results.files_scanned += 1

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

                # Use helper function to add scan result to Pydantic model
                _add_scan_result_to_model(results, scan_metadata, file_result, target)

                _add_asset_to_results(results, target, file_result)

                # Collect and apply license metadata for all files
                license_metadata = collect_license_metadata(target)
                if license_metadata:
                    from .models import FileMetadataModel

                    if target in results.file_metadata:
                        # Update the existing file metadata with license info
                        existing_metadata = results.file_metadata[target].model_dump()
                        combined_metadata = {**existing_metadata, **license_metadata}
                        results.file_metadata[target] = FileMetadataModel(**combined_metadata)
                    else:
                        # Create new file metadata entry for files with no scanner
                        results.file_metadata[target] = FileMetadataModel(**license_metadata)

                if max_total_size > 0 and results.bytes_scanned > max_total_size:
                    _add_issue_to_model(
                        results,
                        f"Total scan size limit exceeded: {results.bytes_scanned} bytes (max: {max_total_size})",
                        severity=IssueSeverity.WARNING.value,
                        location=target,
                        details={"max_total_size": max_total_size},
                    )

                if progress_callback:
                    progress_callback(f"Completed scanning: {target}", 100.0)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        scan_metadata["success"] = False
        _add_issue_to_model(
            results, "Scan interrupted by user", severity=IssueSeverity.INFO.value, details={"interrupted": True}
        )
    except Exception as e:
        logger.exception(f"Error during scan: {e!s}")
        scan_metadata["success"] = False
        _add_issue_to_model(
            results,
            f"Error during scan: {e!s}",
            severity=IssueSeverity.CRITICAL.value,
            details={"exception_type": type(e).__name__},
        )
        _add_error_asset_to_results(results, path)

    # Final timing is handled by finalize_statistics()

    # Consolidate checks for cleaner reporting - temporarily disable while refactoring
    # try:
    #     _consolidate_checks(results)
    # except Exception as e:
    #     logger.warning(f"Error consolidating checks: {e!s}")

    # Add license warnings if any
    try:
        license_warnings = check_commercial_use_warnings(results, strict=config.get("strict_license", False))
        for warning in license_warnings:
            _add_issue_to_model(
                results,
                warning["message"],
                severity=warning["severity"],
                location="",
                details=warning.get("details", {}),
                issue_type=warning.get("type"),
            )
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

    # Check for operational errors in issues
    results.has_errors = (
        any(
            any(indicator in issue.message for indicator in operational_error_indicators)
            for issue in results.issues
            if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        )
        or not scan_metadata["success"]
    )

    # Set success flag for backward compatibility
    results.success = bool(scan_metadata.get("success", True))

    # Finalize statistics and return Pydantic model
    results.finalize_statistics()
    results.deduplicate_issues()
    return results


def determine_exit_code(results: ModelAuditResultModel) -> int:
    """
    Determine the appropriate exit code based on scan results.

    Exit codes:
    - 0: Success, no security issues found
    - 1: Security issues found (scan completed successfully)
    - 2: Operational errors occurred during scanning or no files scanned

    Args:
        results: ModelAuditResultModel with scan results

    Returns:
        Exit code (0, 1, or 2)
    """
    # Check for operational errors first (highest priority)
    if getattr(results, "has_errors", False):
        return 2

    # Check if no files were scanned
    files_scanned = results.files_scanned
    if files_scanned == 0:
        return 2

    # Check for any security findings (warnings, errors, or critical issues)
    issues = results.issues
    if issues:
        # Filter out DEBUG and INFO level issues for exit code determination
        # Only WARNING, ERROR (legacy), and CRITICAL issues should trigger exit code 1
        from modelaudit.scanners.base import IssueSeverity

        security_issues = [
            issue
            for issue in issues
            if hasattr(issue, "severity") and issue.severity in [IssueSeverity.WARNING, IssueSeverity.CRITICAL]
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

    # Check cache configuration
    cache_enabled = config.get("cache_enabled", True)
    cache_dir = config.get("cache_dir")

    # If caching is disabled, proceed with direct scan
    if not cache_enabled:
        return _scan_file_internal(path, config)

    # Use cache manager for cache-enabled scans
    try:
        from .cache import get_cache_manager

        cache_manager = get_cache_manager(cache_dir, enabled=True)

        # Create a wrapper function for the cache manager
        def cached_scan_wrapper(file_path: str) -> dict:
            result = _scan_file_internal(file_path, config)
            return result.to_dict()

        # Get cached result or perform scan
        result_dict = cache_manager.cached_scan(path, cached_scan_wrapper)

        # Convert back to ScanResult
        from .utils.result_conversion import scan_result_from_dict

        return scan_result_from_dict(result_dict)

    except Exception as e:
        # If cache system fails, fall back to direct scanning
        logger.warning(f"Cache system error for {path}: {e}. Falling back to direct scan.")
        return _scan_file_internal(path, config)


def _scan_file_internal(path: str, config: Optional[dict[str, Any]] = None) -> ScanResult:
    """
    Internal implementation of file scanning (cache-agnostic).

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
        sr.add_check(
            name="HuggingFace Cache File Skip",
            passed=True,
            message="HuggingFace cache file skipped (not a model file)",
            severity=IssueSeverity.INFO,
            location=path,
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
            logger.debug(discrepancy_msg)

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
    timeout = config.get("timeout", 3600)

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
                result = scanner.scan_with_cache(path)
        except TimeoutError as e:
            # Handle timeout gracefully
            result = ScanResult(scanner_name=preferred_scanner.name)
            result.add_issue(
                f"Scan timeout: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"timeout": config.get("timeout", 3600), "error": str(e)},
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
                    result = scanner.scan_with_cache(path)
            except TimeoutError as e:
                # Handle timeout gracefully
                result = ScanResult(scanner_name=scanner_class.name)
                result.add_issue(
                    f"Scan timeout: {e}",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"timeout": config.get("timeout", 3600), "error": str(e)},
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
    results: ModelAuditResultModel,
    scan_result: Union[ScanResult, dict[str, Any]],
) -> None:
    """
    Merge a ScanResult object into the ModelAuditResultModel.

    Args:
        results: The existing ModelAuditResultModel
        scan_result: The ScanResult object or dict to merge
    """
    # Use the new direct aggregation method for better performance and type safety
    if isinstance(scan_result, ScanResult):
        results.aggregate_scan_result_direct(scan_result)
    else:
        # Fallback to dict-based aggregation for backward compatibility
        results.aggregate_scan_result(scan_result)
