"""Core scanning engine for orchestrating model file security analysis."""

import hashlib
import logging
import os
import time
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from modelaudit.integrations.license_checker import (
    LICENSE_FILES,
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.models import ModelAuditResultModel, ScanConfigModel, create_initial_audit_result
from modelaudit.scanners import _registry
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, IssueSeverity, ScanResult
from modelaudit.telemetry import record_file_type_detected, record_issue_found, record_scanner_used
from modelaudit.utils import is_within_directory, resolve_dvc_file, should_skip_file
from modelaudit.utils.file.detection import (
    detect_file_format,
    detect_file_format_from_magic,
    detect_format_from_extension,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
    validate_file_type,
)
from modelaudit.utils.file.handlers import (
    scan_advanced_large_file,
    should_use_advanced_handler,
)
from modelaudit.utils.file.large_file_handler import (
    scan_large_file,
    should_use_large_file_handler,
)
from modelaudit.utils.file.streaming import stream_analyze_file
from modelaudit.utils.helpers.assets import asset_from_scan_result
from modelaudit.utils.helpers.cache_decorator import cached_scan
from modelaudit.utils.helpers.interrupt_handler import check_interrupted
from modelaudit.utils.helpers.types import (
    FilePath,
    ProgressCallback,
)
from modelaudit.utils.lfs import check_lfs_pointer, get_lfs_issue_details, get_lfs_remediation_steps

logger = logging.getLogger("modelaudit.core")

_OPERATIONAL_ERROR_METADATA_KEY = "operational_error"
_OPERATIONAL_ERROR_REASON_METADATA_KEY = "operational_error_reason"
_SCAN_OUTCOME_METADATA_KEY = "scan_outcome"

HEADER_FORMAT_TO_SCANNER_ID = {
    "pickle": "pickle",
    "pytorch_binary": "pytorch_binary",
    "hdf5": "keras_h5",
    "keras": "keras_h5",
    "safetensors": "safetensors",
    "tensorflow_directory": "tf_savedmodel",
    "protobuf": "tf_savedmodel",
    "tf_metagraph": "tf_metagraph",
    "tar": "tar",
    "zip": "zip",
    "onnx": "onnx",
    "gguf": "gguf",
    "ggml": "gguf",
    "numpy": "numpy",
    "openvino": "openvino",
    "pmml": "pmml",
    "cntk": "cntk",
    "lightgbm": "lightgbm",
    "torch7": "torch7",
    "catboost": "catboost",
    "rknn": "rknn",
    "mxnet": "mxnet",
    "nemo": "nemo",
    "llamafile": "llamafile",
    "tflite": "tflite",
    "coreml": "coreml",
    "paddle": "paddle",
    "tensorrt": "tensorrt",
    "flax_msgpack": "flax_msgpack",
    "r_serialized": "r_serialized",
    "executorch": "executorch",
    "compressed": "compressed",
    "sevenzip": "sevenzip",
    "skops": "skops",
    "torchserve_mar": "torchserve_mar",
    "joblib": "joblib",
    "xgboost": "xgboost",
    "jax_checkpoint": "jax_checkpoint",
}


def _mark_operational_scan_error(scan_result: ScanResult, reason: str) -> None:
    """Mark a scan result as an operational failure for exit-code aggregation."""
    scan_result.metadata[_OPERATIONAL_ERROR_METADATA_KEY] = True
    scan_result.metadata[_OPERATIONAL_ERROR_REASON_METADATA_KEY] = reason


def _scan_result_has_operational_error(scan_result: ScanResult) -> bool:
    """Return True when a scan result represents an operational failure."""
    metadata = scan_result.metadata or {}
    explicit_flag = metadata.get(_OPERATIONAL_ERROR_METADATA_KEY)
    if explicit_flag is not None:
        return bool(explicit_flag)

    return False


def _results_have_operational_error(results: ModelAuditResultModel) -> bool:
    """Return True when aggregated results include an operational failure."""
    if getattr(results, "has_errors", False):
        return True

    return any(
        bool(metadata.get(_OPERATIONAL_ERROR_METADATA_KEY)) for metadata in (results.file_metadata or {}).values()
    )


def _metadata_has_scan_outcome(metadata: Any, outcome: str) -> bool:
    """Return True when metadata reports the requested scan outcome."""
    if metadata is None:
        return False
    if isinstance(metadata, dict):
        return metadata.get(_SCAN_OUTCOME_METADATA_KEY) == outcome

    getter = getattr(metadata, "get", None)
    if callable(getter):
        try:
            value = getter(_SCAN_OUTCOME_METADATA_KEY)
            return bool(value == outcome)
        except Exception:
            return False

    return getattr(metadata, _SCAN_OUTCOME_METADATA_KEY, None) == outcome


def _results_have_inconclusive_outcome(results: ModelAuditResultModel) -> bool:
    """Return True when any scanned file completed with an explicit inconclusive outcome."""
    return any(
        _metadata_has_scan_outcome(metadata, INCONCLUSIVE_SCAN_OUTCOME)
        for metadata in (results.file_metadata or {}).values()
    )


def _results_have_security_findings(results: ModelAuditResultModel) -> bool:
    """Return True when WARNING/CRITICAL issues were reported."""
    return any(
        hasattr(issue, "severity") and issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL)
        for issue in (results.issues or [])
    )


def _results_should_be_unsuccessful(results: ModelAuditResultModel) -> bool:
    """Return True when the aggregate result should not be considered successful."""
    if _results_have_operational_error(results):
        return True

    return _results_have_inconclusive_outcome(results) and not _results_have_security_findings(results)


def _to_telemetry_severity(severity: Any) -> str:
    """Normalize severity values to stable telemetry strings."""
    if hasattr(severity, "value"):
        return str(severity.value).lower()
    if hasattr(severity, "name"):
        return str(severity.name).lower()

    severity_str = str(severity).lower()
    if severity_str.startswith("issueseverity."):
        severity_str = severity_str.split(".", 1)[1]
    return severity_str


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
    if _scan_result_has_operational_error(file_result):
        scan_metadata["has_operational_errors"] = True

    # Convert and add issues
    for issue in file_result.issues:
        issue_dict = issue.to_dict() if hasattr(issue, "to_dict") else issue
        if isinstance(issue_dict, dict):
            record_issue_found(
                issue_type=str(issue_dict.get("message", "unknown_issue")),
                severity=_to_telemetry_severity(issue_dict.get("severity", "unknown")),
                scanner=file_result.scanner_name,
                file_path=file_path,
            )
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


def _select_preferred_scanner_id(path: str, header_format: str, ext: str) -> str | None:
    """Select a scanner by trusted file structure, not just suffix."""
    if header_format == "zip":
        if is_torchserve_mar_archive(path):
            return "torchserve_mar"
        if is_keras_zip_archive(path, allow_config_only=ext == ".keras"):
            return "keras_zip"
        if is_pytorch_zip_archive(path):
            return "pytorch_zip"
        if is_executorch_archive(path):
            return "executorch"
        if is_skops_archive(path):
            return "skops"
        if ext == ".skops":
            return "skops"
        if ext == ".joblib":
            return "joblib"

        if ext == ".bin":
            # ZIP-backed torch.save() .bin files are routed through the pickle scanner,
            # which already understands the ZIP serialization used by PyTorch.
            return "pickle"
        return "zip"

    if header_format == "hdf5":
        return "keras_h5"

    if ext == ".joblib" and header_format in {"compressed", "pickle"}:
        return "joblib"

    if header_format == "tar" and ext == ".nemo":
        return "nemo"

    return HEADER_FORMAT_TO_SCANNER_ID.get(header_format)


def _add_issue_to_model(
    results: ModelAuditResultModel,
    message: str,
    severity: str = "warning",
    location: str | None = None,
    details: dict | None = None,
    issue_type: str | None = None,
) -> None:
    """Helper function to add an issue directly to the Pydantic model."""
    import time

    from .scanners.base import Issue

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


def _normalize_streamed_location(location: str | None, report_path: str, resolved_path: str) -> str | None:
    """Rewrite streamed result locations to the original source path when needed."""
    if not location or report_path == resolved_path:
        return location

    if location == resolved_path:
        return report_path

    if not location.startswith(resolved_path):
        return location

    suffix = location[len(resolved_path) :]
    if suffix and suffix[0] not in {":", " ", "(", "[", "/", "\\"}:
        return location

    return f"{report_path}{suffix}"


def _serialize_streamed_records(records: list[Any], report_path: str, resolved_path: str) -> list[dict[str, Any]]:
    """Convert streamed issues/checks into dicts with source-path locations."""
    serialized: list[dict[str, Any]] = []
    for record in records:
        record_dict = record.to_dict() if hasattr(record, "to_dict") else record
        if not isinstance(record_dict, dict):
            continue

        normalized_record = dict(record_dict)
        location = normalized_record.get("location")
        if isinstance(location, str):
            normalized_record["location"] = _normalize_streamed_location(location, report_path, resolved_path)

        serialized.append(normalized_record)

    return serialized


def _calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file for deduplication purposes.

    Raises:
        Exception: If file cannot be hashed (security: prevents hash collision attacks)
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(8192), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def _group_files_by_content(file_paths: list[str]) -> dict[str, list[str]]:
    """Group files by their content hash to avoid scanning duplicates.

    Args:
        file_paths: List of file paths to group

    Returns:
        Dictionary mapping content hash to list of file paths with that content
    """
    content_groups: dict[str, list[str]] = defaultdict(list)

    for file_path in file_paths:
        try:
            content_hash = _calculate_file_hash(file_path)
            content_groups[content_hash].append(file_path)
        except Exception as e:
            # Log error but continue with other files to prevent single I/O failure from aborting entire scan
            logger.warning(f"Failed to hash file {file_path}: {e}. Skipping deduplication for this file.")
            # Add file with unique hash to ensure it gets scanned independently
            content_groups[f"unhashable_{id(file_path)}"].append(file_path)

    # Log information about duplicate content found
    for content_hash, paths in content_groups.items():
        if len(paths) > 1:
            logger.debug(f"Found {len(paths)} files with identical content (hash: {content_hash[:16]})")
            for path in paths:
                logger.debug(f"  - {path}")

    return dict(content_groups)


def _path_has_part(path: Path, part: str) -> bool:
    """Return True if any path segment matches part (case-insensitive)."""
    part_lower = part.lower()
    return any(segment.lower() == part_lower for segment in path.parts)


def _find_hf_cache_root(path: Path) -> Path | None:
    """Return the HuggingFace cache root containing models--* if present."""
    for index, segment in enumerate(path.parts):
        if (
            segment.lower().startswith("models--")
            and index >= 3
            and [part.lower() for part in path.parts[index - 3 : index]] == [".cache", "huggingface", "hub"]
        ):
            return Path(*path.parts[: index + 1])
    return None


def _resolve_directory_scan_target(
    file_path: Path,
    base_dir: Path,
    *,
    is_hf_cache: bool,
    hf_cache_root: Path | None,
    results: ModelAuditResultModel,
) -> tuple[Path | None, bool]:
    """Resolve a directory entry and reject symlink traversal outside the scan root."""
    resolved_file = file_path.resolve()

    # Check if this is a HuggingFace cache symlink scenario
    is_hf_cache_symlink = False
    if file_path.is_symlink() and is_hf_cache and _path_has_part(file_path, "snapshots"):
        try:
            link_target = os.readlink(file_path)
        except OSError as e:
            _add_issue_to_model(
                results,
                "Broken symlink encountered",
                severity=IssueSeverity.INFO.value,
                location=str(file_path),
                details={"error": str(e)},
            )
            return None, False

        # Resolve the relative link target
        resolved_target = (file_path.parent / link_target).resolve()
        # Check if target is in the blobs directory of the same model cache
        if hf_cache_root is not None:
            blobs_root = hf_cache_root / "blobs"
            if is_within_directory(str(blobs_root), str(resolved_target)):
                is_hf_cache_symlink = True
                # Update the resolved_file to the actual target for scanning
                resolved_file = resolved_target

    if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(resolved_file)):
        _add_issue_to_model(
            results,
            "Path traversal outside scanned directory",
            severity=IssueSeverity.CRITICAL.value,
            location=str(file_path),
            details={"resolved_path": str(resolved_file)},
        )
        return None, False

    return resolved_file, is_hf_cache_symlink


def _extract_primary_asset_from_location(location: str) -> str:
    """Extract primary asset path from location string.

    Args:
        location: Location string in various formats

    Returns:
        Primary asset path, or "unknown" if cannot be determined
    """
    if not location or not isinstance(location, str):
        return "unknown"

    # Locations are single paths. Duplicate copies are tracked separately in
    # details["duplicate_files"] to avoid ambiguous delimiter encoding.
    primary_location = location.strip()

    if not primary_location:
        return "unknown"

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
        details = check.get("details")
        zip_entry_id = details.get("zip_entry_id") if isinstance(details, dict) else None
        zip_entry = details.get("zip_entry") if isinstance(details, dict) else None

        if isinstance(zip_entry_id, str) and zip_entry_id:
            asset_group = f"{primary_asset}:{zip_entry_id}"
        elif isinstance(zip_entry, str) and zip_entry:
            asset_group = f"{primary_asset}:{zip_entry}"
        else:
            asset_group = primary_asset

        group_key = (check_name, asset_group)
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


def _extract_failure_context(group_checks: list[dict[str, Any]]) -> tuple[str | None, str | None]:
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
    timestamps = [c.get("timestamp", 0) for c in group_checks if isinstance(c.get("timestamp"), int | float)]
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

    # Filter for success rate: include all passed checks + failed WARNING/CRITICAL checks
    # Exclude failed INFO/DEBUG checks from success rate (they're informational)
    def is_failed_info_or_debug(check):
        if check.get("status") != "failed":
            return False
        severity = check.get("severity", "")
        # Check both string and enum values for compatibility
        return severity in ("info", "debug", IssueSeverity.INFO.value, IssueSeverity.DEBUG.value)

    # Exclude only failed INFO/DEBUG checks from success rate
    security_checks = [c for c in consolidated_checks if not is_failed_info_or_debug(c)]

    total_checks = len(security_checks)
    passed_checks = sum(1 for c in security_checks if c.get("status") == "passed")
    failed_checks = sum(1 for c in security_checks if c.get("status") == "failed")
    skipped_checks = total_checks - passed_checks - failed_checks

    # Debug logging
    info_debug_excluded = len(consolidated_checks) - len(security_checks)
    logger.debug(
        f"Check statistics: {total_checks} total ({info_debug_excluded} INFO/DEBUG excluded), "
        f"{passed_checks} passed, {failed_checks} failed"
    )

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
    logger.debug(f"Check consolidation: {original_count} -> {total_checks} ({reduction_count} duplicates removed)")

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
        statuses = [c.get("status") for c in group_checks]
        failed_count = sum(s == "failed" for s in statuses)
        passed_count = sum(s == "passed" for s in statuses)
        if failed_count:
            consolidated_status = "failed"
        elif passed_count:
            consolidated_status = "passed"
        else:
            consolidated_status = "skipped"

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
    path: FilePath,
    blacklist_patterns: list[str] | None = None,
    timeout: int = 3600,  # 1 hour for large models (up to 8GB+)
    max_file_size: int = 0,  # 0 means unlimited - support any size
    max_total_size: int = 0,  # 0 means unlimited
    strict_license: bool = False,
    progress_callback: ProgressCallback | None = None,
    skip_file_types: bool = True,
    **kwargs: Any,
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
        "has_operational_errors": False,
        "scanners": [],  # Track the scanners used (different from scanner_names)
    }
    # Track file hashes for aggregate hash computation
    file_hashes: list[str] = []

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
                    results.files_scanned += 1

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
            try:
                _consolidate_checks(results)
            except Exception as e:
                logger.warning(f"Error consolidating checks ({type(e).__name__}): {e!s}", exc_info=e)
            results.has_errors = bool(scan_metadata.get("has_operational_errors", False))
            results.success = not _results_should_be_unsuccessful(results)
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
            hf_cache_root = _find_hf_cache_root(base_dir)
            is_hf_cache = (
                hf_cache_root is not None
                and _path_has_part(base_dir, "huggingface")
                and _path_has_part(base_dir, "hub")
            )
            scanned_paths: set[str] = set()

            # First pass: collect all file paths that need scanning
            files_to_scan: list[str] = []
            for root, _, files in os.walk(path, followlinks=False):
                for file in files:
                    file_path = os.path.join(root, file)

                    # HuggingFace cache bookkeeping files should never surface as
                    # scan assets or SBOM components for downloaded models.
                    if _is_huggingface_cache_file(file_path):
                        logger.debug(f"Skipping HuggingFace cache file: {file_path}")
                        continue

                    resolved_file, is_hf_cache_symlink = _resolve_directory_scan_target(
                        Path(file_path),
                        base_dir,
                        is_hf_cache=is_hf_cache,
                        hf_cache_root=hf_cache_root,
                        results=results,
                    )
                    if resolved_file is None:
                        continue

                    # Skip non-model files early if filtering is enabled
                    # Note: skip_file_types parameter already contains the correct value
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

                    # Collect valid content hashes for aggregate hash computation
                    # Skip "unhashable_" prefix entries (those are placeholder hashes for files that failed to hash)
                    if not content_hash.startswith("unhashable_"):
                        file_hashes.append(content_hash)

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
                        if _scan_result_has_operational_error(file_result):
                            scan_metadata["has_operational_errors"] = True
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
                                record_issue_found(
                                    issue_type=str(issue_dict.get("message", "unknown_issue")),
                                    severity=_to_telemetry_severity(issue_dict.get("severity", "unknown")),
                                    scanner=file_result.scanner_name,
                                    file_path=representative_file,
                                )
                                if not issue_dict.get("location"):
                                    issue_dict["location"] = representative_file

                                if len(file_paths) > 1:
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
                                    if not check_dict.get("location"):
                                        check_dict["location"] = representative_file

                                    if len(file_paths) > 1:
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
                                severity=IssueSeverity.INFO.value,
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
                                severity=IssueSeverity.INFO.value,
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
                logger.warning("Scan terminated early due to total size limit")
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

                results.files_scanned += 1

                # Compute hash for single file to enable aggregate hash
                try:
                    file_hash = _calculate_file_hash(target)
                    file_hashes.append(file_hash)
                except Exception as e:
                    logger.debug(f"Failed to hash file {target}: {e}")
                    # Continue without hash - not a critical error

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
                        severity=IssueSeverity.INFO.value,
                        location=target,
                        details={"max_total_size": max_total_size},
                    )

                if progress_callback:
                    progress_callback(f"Completed scanning: {target}", 100.0)

    except KeyboardInterrupt:
        logger.debug("Scan interrupted by user")
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
            severity=IssueSeverity.INFO.value,
            details={"exception_type": type(e).__name__},
        )
        _add_error_asset_to_results(results, path)

    # Final timing is handled by finalize_statistics()

    # Consolidate checks for cleaner reporting
    try:
        _consolidate_checks(results)
    except Exception as e:
        logger.warning(f"Error consolidating checks ({type(e).__name__}): {e!s}", exc_info=e)

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

    # Determine if there were operational scan errors vs security findings.
    results.has_errors = bool(scan_metadata.get("has_operational_errors", False) or not scan_metadata["success"])

    # Set success flag for backward compatibility
    results.success = not _results_should_be_unsuccessful(results)

    # Compute aggregate content hash if we collected file hashes
    if file_hashes:
        from .utils.helpers.secure_hasher import compute_aggregate_hash

        results.content_hash = compute_aggregate_hash(file_hashes)
        logger.info(f"Computed aggregate content hash from {len(file_hashes)} file(s): {results.content_hash}")

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
    - 2: Operational errors occurred during scanning, the scan outcome was
         inconclusive without any WARNING/CRITICAL findings, or no files were
         scanned and no security issues were found

    Args:
        results: ModelAuditResultModel with scan results

    Returns:
        Exit code (0, 1, or 2)
    """
    # Check for operational errors first (highest priority)
    if _results_have_operational_error(results):
        return 2

    # Security findings take precedence over inconclusive outcomes so the
    # caller still gets exit code 1 when genuine risks were identified.
    if _results_have_security_findings(results):
        return 1

    if _results_have_inconclusive_outcome(results):
        return 2

    # Check if no files were scanned
    files_scanned = results.files_scanned
    if files_scanned == 0:
        return 2

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
    path_obj = Path(path)

    # Download lock files are HuggingFace bookkeeping files regardless of cache layout.
    if filename.endswith(".lock"):
        return True

    # Only skip HuggingFace .metadata files in known cache/download layouts.
    if filename.endswith(".metadata"):
        hf_cache_root = _find_hf_cache_root(path_obj)
        if hf_cache_root is not None and hf_cache_root.parent.name.lower() == "hub":
            try:
                relative_parts = path_obj.relative_to(hf_cache_root).parts
            except ValueError:
                relative_parts = ()

            if relative_parts and relative_parts[0] in {"snapshots", "blobs", "refs"}:
                return True

        normalized_parts = [part.lower() for part in path_obj.parent.parts]
        if len(normalized_parts) >= 3 and normalized_parts[-3:] == [".cache", "huggingface", "download"]:
            return True

    # Check for specific HuggingFace cache metadata files
    # We no longer skip all HuggingFace cache files since we handle symlinks properly now

    # Check for Git-related files that are commonly cached
    if filename in [".gitignore", ".gitattributes", "main", "HEAD"]:
        return True

    # Check if file is in refs directory (Git references, not actual model files)
    return bool("/refs/" in path and filename in ["main", "HEAD"])


@cached_scan()
def scan_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
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

    # Delegate to internal implementation - cache decorator handles caching
    return _scan_file_internal(path, config)


def _scan_file_internal(path: str, config: dict[str, Any] | None = None) -> ScanResult:
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

    # Check for Git LFS pointer files (text pointers instead of actual model content)
    # This is a common issue when cloning repos without `git lfs pull`
    is_lfs, lfs_info = check_lfs_pointer(path)
    if is_lfs:
        sr = ScanResult(scanner_name="lfs_check")
        details = get_lfs_issue_details(path, lfs_info)
        details["remediation"] = get_lfs_remediation_steps()

        if lfs_info:
            message = (
                f"Git LFS pointer detected - file is {details['actual_size_bytes']} bytes "
                f"but should be {lfs_info.format_expected_size()}"
            )
        else:
            message = "Git LFS pointer detected - this is a text pointer, not the actual model file"

        # add_check with passed=False automatically creates an Issue as well
        sr.add_check(
            name="Git LFS Pointer Detection",
            passed=False,
            message=message,
            severity=IssueSeverity.CRITICAL,
            location=path,
            why=(
                "This file is a Git LFS pointer (a small text file that references the actual content) "
                "rather than the actual model weights. The model cannot be loaded in its current state. "
                "Run 'git lfs pull' to download the actual file."
            ),
            details=details,
        )
        sr.finish(success=False)
        return sr

    # Get file size for later checks
    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        sr = ScanResult(scanner_name="error")
        sr.add_check(
            name="File Size Check",
            passed=False,
            message=f"Error checking file size: {e}",
            severity=IssueSeverity.INFO,
            details={"error": str(e), "path": path},
        )
        _mark_operational_scan_error(sr, "file_size_check_failed")
        sr.finish(success=False)
        return sr

    # Check if we should use extreme handler BEFORE applying size limits
    # Extreme handler bypasses size limits for large models
    use_extreme_handler = should_use_advanced_handler(path)

    # Check file size limit only if NOT using extreme handler
    max_file_size = config.get("max_file_size", 0)  # Default unlimited
    if not use_extreme_handler and max_file_size > 0 and file_size > max_file_size:
        sr = ScanResult(scanner_name="size_check")
        sr.add_check(
            name="File Size Limit Check",
            passed=False,
            message=f"File too large to scan: {file_size} bytes (max: {max_file_size})",
            severity=IssueSeverity.INFO,
            details={
                "file_size": file_size,
                "max_file_size": max_file_size,
                "path": path,
                "hint": "Consider using extreme large model support for files over 50GB",
            },
        )
        _mark_operational_scan_error(sr, "max_file_size_exceeded")
        sr.finish(success=False)
        return sr

    logger.debug(f"Processing: {path}")

    header_format = detect_file_format(path)
    ext_format = detect_format_from_extension(path)
    ext = os.path.splitext(path)[1].lower()

    # Record telemetry for file type detection
    detected_format = header_format if header_format != "unknown" else ext_format
    record_file_type_detected(path, detected_format)

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
        # Suppress expected container-vs-extension differences for known wrapper formats.
        if not (
            (ext_format == "pytorch_binary" and header_format in ["zip", "pickle"] and ext == ".bin")
            or (ext_format == "pytorch_binary" and header_format == "pickle" and ext in [".pt", ".pth"])
            or (ext_format == "keras" and header_format in ["zip", "hdf5"])
            or (ext_format == "skops" and header_format == "zip" and ext == ".skops")
        ):
            discrepancy_msg = f"File extension indicates {ext_format} but header indicates {header_format}."
            logger.debug(discrepancy_msg)

    # Prefer scanners based on trusted structure rather than the filename alone.
    preferred_scanner: type[BaseScanner] | None = None
    scanner_id = _select_preferred_scanner_id(path, header_format, ext)
    if scanner_id:
        preferred_scanner = _registry.load_scanner_by_id(scanner_id)

    result: ScanResult | None

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
            # Record scanner usage telemetry
            scan_start = time.time()

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

            # Record scanner usage telemetry
            scan_duration = time.time() - scan_start
            record_scanner_used(preferred_scanner.name, detected_format, scan_duration)
        except TimeoutError as e:
            # Handle timeout gracefully
            result = ScanResult(scanner_name=preferred_scanner.name)
            result.add_check(
                name="Scan Timeout Check",
                passed=False,
                message=f"Scan timeout: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"timeout": config.get("timeout", 3600), "error": str(e)},
            )
            _mark_operational_scan_error(result, "scan_timeout")
            result.finish(success=False)
    else:
        # Use registry's lazy loading method to avoid loading all scanners
        scanner_class = _registry.get_scanner_for_path(path)
        if scanner_class:
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)

            try:
                # Record scanner usage telemetry
                scan_start = time.time()

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

                # Record scanner usage telemetry
                scan_duration = time.time() - scan_start
                record_scanner_used(scanner_class.name, detected_format, scan_duration)
            except TimeoutError as e:
                # Handle timeout gracefully
                result = ScanResult(scanner_name=scanner_class.name)
                result.add_check(
                    name="Scan Timeout Check",
                    passed=False,
                    message=f"Scan timeout: {e}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"timeout": config.get("timeout", 3600), "error": str(e)},
                )
                _mark_operational_scan_error(result, "scan_timeout")
                result.finish(success=False)
        else:
            format_ = header_format
            sr = ScanResult(scanner_name="unknown")
            if format_ == "unknown":
                # Not a recognized model format — skip silently
                logger.debug(f"Skipping unrecognized format file: {path}")
            else:
                # Known format but no scanner available
                sr.add_check(
                    name="Format Detection",
                    passed=False,
                    message=f"Unknown or unhandled format: {format_}",
                    severity=IssueSeverity.DEBUG,
                    details={"format": format_, "path": path},
                )
            result = sr

    if discrepancy_msg:
        # Determine severity based on whether it's a validation failure or just a discrepancy
        severity = IssueSeverity.WARNING if not file_type_valid else IssueSeverity.DEBUG
        # For validation failures, use the actual magic format
        detail_header_format = magic_format if not file_type_valid else header_format
        result.add_check(
            name="Format Validation",
            passed=False,
            message=discrepancy_msg + " Using header-based detection.",
            severity=severity,
            location=path,
            details={
                "extension_format": ext_format,
                "header_format": detail_header_format,
                "file_type_validation_failed": not file_type_valid,
            },
        )

    # Ensure bytes_scanned reflects the actual file size even when a scanner
    # returns early (e.g. missing optional dependency, parse error).  The file
    # size was already computed above via os.path.getsize and is guaranteed to
    # be accurate.  Without this fallback the scan summary reports "Size: 0
    # bytes" for every file whose scanner didn't explicitly set the field.
    if result.bytes_scanned == 0 and file_size > 0:
        result.bytes_scanned = file_size

    return result


def merge_scan_result(
    results: ModelAuditResultModel,
    scan_result: ScanResult | dict[str, Any],
) -> None:
    """
    Merge a ScanResult object into the ModelAuditResultModel.

    Args:
        results: The existing ModelAuditResultModel
        scan_result: The ScanResult object or dict to merge
    """
    # Record telemetry for issues before aggregation
    if isinstance(scan_result, ScanResult):
        file_path = scan_result.file_path if hasattr(scan_result, "file_path") else None
        for issue in scan_result.issues:
            record_issue_found(
                issue.message,
                issue.severity.name if hasattr(issue.severity, "name") else str(issue.severity),
                scan_result.scanner_name,
                file_path=file_path,
            )
        # Use the new direct aggregation method for better performance and type safety
        results.aggregate_scan_result_direct(scan_result)
    else:
        # Fallback to dict-based aggregation for backward compatibility with telemetry
        file_path = scan_result.get("file_path")
        for issue in scan_result.get("issues", []):
            record_issue_found(
                issue.get("message", "unknown_issue"),
                issue.get("severity", "unknown"),
                scan_result.get("scanner_name", "unknown"),
                file_path=file_path,
            )
        results.aggregate_scan_result(scan_result)


def scan_model_streaming(
    file_generator: Iterator[tuple[Path, bool]],
    timeout: int = 3600,
    progress_callback: ProgressCallback | None = None,
    delete_after_scan: bool = True,
    scan_root: FilePath | None = None,
    **kwargs: Any,
) -> ModelAuditResultModel:
    """
    Scan model files from a generator in streaming mode.

    Downloads files one at a time, scans immediately, computes hash, and optionally
    deletes to minimize disk usage. Computes aggregate content hash at the end.

    Args:
        file_generator: Generator yielding (file_path, is_last) tuples
        timeout: Scan timeout in seconds
        progress_callback: Optional callback for progress reporting
        delete_after_scan: Whether to delete files after scanning (default: True)
        scan_root: Optional root directory for local streaming traversal validation
        **kwargs: Additional arguments passed to scanners

    Returns:
        ModelAuditResultModel with scan results and content_hash field
    """
    from .models import convert_assets_to_models
    from .utils.helpers.assets import asset_from_scan_result
    from .utils.helpers.file_hash import compute_sha256_hash
    from .utils.helpers.secure_hasher import compute_aggregate_hash

    start_time = time.time()
    results = create_initial_audit_result()
    file_hashes: list[str] = []
    files_processed = 0

    base_dir = Path(scan_root).resolve() if scan_root is not None else None
    hf_cache_root = _find_hf_cache_root(base_dir) if base_dir is not None else None
    is_hf_cache = (
        base_dir is not None
        and hf_cache_root is not None
        and _path_has_part(base_dir, "huggingface")
        and _path_has_part(base_dir, "hub")
    )

    try:
        for file_path, _is_last in file_generator:
            source_path = Path(file_path)
            scan_path = source_path
            report_path = str(source_path)

            # Check for interruption
            check_interrupted()

            # Check timeout
            if time.time() - start_time > timeout:
                results.has_errors = True
                logger.error(f"Streaming scan timeout after {timeout}s")
                break

            try:
                if base_dir is not None:
                    resolved_path, _is_hf_cache_symlink = _resolve_directory_scan_target(
                        source_path,
                        base_dir,
                        is_hf_cache=is_hf_cache,
                        hf_cache_root=hf_cache_root,
                        results=results,
                    )
                    if resolved_path is None:
                        continue
                    scan_path = resolved_path

                # Compute file hash
                if progress_callback:
                    progress_callback(f"Hashing {source_path.name}", (files_processed / (files_processed + 1)) * 100)

                file_hash = compute_sha256_hash(scan_path)
                file_hashes.append(file_hash)

                # Scan the file
                if progress_callback:
                    progress_callback(f"Scanning {source_path.name}", (files_processed / (files_processed + 1)) * 100)

                # Build config dict for scan_file
                scan_config = {
                    "timeout": timeout - int(time.time() - start_time),
                    **kwargs,
                }

                scan_result = scan_file(
                    str(scan_path),
                    config=scan_config,
                )

                # Merge results
                if scan_result:
                    resolved_report_path = str(scan_path)
                    metadata_dict = dict(scan_result.metadata or {})
                    metadata_dict.setdefault("file_size", scan_path.stat().st_size)
                    if report_path != resolved_report_path:
                        metadata_dict.setdefault("source_path", report_path)
                        metadata_dict.setdefault("resolved_path", resolved_report_path)
                    operational_scan_failure = _scan_result_has_operational_error(scan_result)

                    existing_hashes = metadata_dict.get("file_hashes")
                    if isinstance(existing_hashes, dict):
                        existing_hashes.setdefault("sha256", file_hash)
                    else:
                        metadata_dict["file_hashes"] = {"sha256": file_hash}

                    # Use dict-based aggregation to avoid import issues
                    scan_result_dict = {
                        "bytes_scanned": scan_result.bytes_scanned,
                        "files_scanned": 1,  # Each scan_result represents one file
                        # Preserve the main scan semantics: success=False does not
                        # imply an operational error when the scanner completed
                        # and only reported informational integrity findings.
                        "has_errors": operational_scan_failure,
                        "success": scan_result.success,
                        "issues": _serialize_streamed_records(
                            list(scan_result.issues or []),
                            report_path,
                            resolved_report_path,
                        ),
                        "checks": _serialize_streamed_records(
                            list(scan_result.checks or []),
                            report_path,
                            resolved_report_path,
                        ),
                        "scanners": [scan_result.scanner_name] if scan_result.scanner_name else [],
                        "file_metadata": {report_path: metadata_dict},
                    }
                    results.aggregate_scan_result(scan_result_dict)

                    # Add asset
                    asset = asset_from_scan_result(report_path, scan_result, metadata=metadata_dict)
                    if asset:
                        results.assets.extend(convert_assets_to_models([asset]))

                files_processed += 1

            except Exception as e:
                logger.error(f"Error processing {source_path}: {e}", exc_info=True)
                results.has_errors = True

            finally:
                # Delete file after scanning if requested
                if delete_after_scan and source_path.exists():
                    try:
                        source_path.unlink()
                        logger.debug(f"Deleted {source_path} after scanning")
                    except Exception as e:
                        logger.warning(f"Failed to delete {source_path}: {e}")

        # Compute aggregate hash from all file hashes
        if file_hashes:
            results.content_hash = compute_aggregate_hash(file_hashes)
            logger.info(f"Computed aggregate content hash: {results.content_hash}")

        # Finalize statistics
        results.finalize_statistics()
        results.success = not _results_should_be_unsuccessful(results)

    except Exception as e:
        logger.error(f"Streaming scan failed: {e}")
        results.has_errors = True
        raise

    return results
