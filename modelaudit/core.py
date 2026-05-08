"""Core scanning engine for orchestrating model file security analysis."""

import hashlib
import itertools
import logging
import os
import time
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import modelaudit.core_results as core_results
from modelaudit.integrations.license_checker import (
    LICENSE_FILES,
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.models import ModelAuditResultModel, ScanConfigModel, create_initial_audit_result
from modelaudit.scanner_results import Issue, IssueSeverity, ScanResult
from modelaudit.scanner_selection import (
    SCANNER_SELECTION_PREFERRED_KIND,
    add_scanner_selection_skip_check,
    make_scanner_selection_skip_result,
    normalize_scanner_selection_config,
    policy_from_config,
    selected_scanner_extensions,
)
from modelaudit.scanners import _registry
from modelaudit.scanners.archive_dispatch import NESTED_SCAN_CALLBACK_CONFIG_KEY
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, BaseScanner
from modelaudit.telemetry import record_file_type_detected, record_issue_found, record_scanner_used
from modelaudit.utils import is_within_directory, resolve_dvc_file, should_skip_file
from modelaudit.utils.file.detection import (
    XML_MODEL_INCONCLUSIVE_FORMAT,
    detect_file_format,
    detect_file_format_from_magic,
    detect_format_from_extension,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
    validate_file_type_with_formats,
)
from modelaudit.utils.file.handlers import (
    ShardedModelDetector,
    scan_advanced_large_file,
    should_use_advanced_handler,
)
from modelaudit.utils.file.large_file_handler import (
    scan_large_file,
    should_use_large_file_handler,
)
from modelaudit.utils.file.streaming import stream_analyze_file
from modelaudit.utils.helpers.cache_decorator import cached_scan
from modelaudit.utils.helpers.interrupt_handler import check_interrupted
from modelaudit.utils.helpers.types import (
    FilePath,
    ProgressCallback,
)
from modelaudit.utils.lfs import check_lfs_pointer, get_lfs_issue_details, get_lfs_remediation_steps
from modelaudit.utils.sources._huggingface_cache import (
    _find_hf_cache_root,
    _get_hf_cache_roots,
    _path_has_part,
    _resolve_hf_cache_path,
)

logger = logging.getLogger("modelaudit.core")

_add_asset_to_results = core_results.add_asset_to_results
_add_error_asset_to_results = core_results.add_error_asset_to_results
_DIRECTORY_PRECOUNT_CHILD_LIMIT = 1000


def _count_immediate_children_up_to(path: Path, limit: int) -> int:
    """Count at most `limit` immediate children for directory-size heuristics."""
    return sum(1 for _child in itertools.islice(path.iterdir(), limit))


def _count_files_up_to(path: Path, limit: int) -> int | None:
    """Return an exact recursive file count only while it stays within `limit`."""
    count = sum(1 for candidate in itertools.islice((item for item in path.rglob("*") if item.is_file()), limit + 1))
    return None if count > limit else count


_add_issue_to_model = core_results.add_issue_to_model
_add_scan_result_to_model = core_results.add_scan_result_to_model
_consolidate_checks = core_results.consolidate_checks
_mark_inconclusive_scan_outcome = core_results.mark_inconclusive_scan_outcome
_mark_operational_scan_error = core_results.mark_operational_scan_error
_results_should_be_unsuccessful = core_results.results_should_be_unsuccessful
_scan_result_has_operational_error = core_results.scan_result_has_operational_error
_serialize_streamed_records = core_results.serialize_streamed_records
_to_telemetry_severity = core_results.to_telemetry_severity
_normalize_unclassified_scan_failure = core_results.normalize_unclassified_scan_failure
determine_exit_code = core_results.determine_exit_code
merge_scan_result = core_results.merge_scan_result

HEADER_FORMAT_TO_SCANNER_ID = _registry.get_header_format_to_scanner_ids()
_COMPRESSED_HEADER_FORMATS = frozenset({"compressed", "gzip", "bzip2", "xz", "lz4", "zlib"})
_R_SERIALIZED_EXTENSIONS = frozenset({".rds", ".rda", ".rdata"})
_XGBOOST_BINARY_EXTENSIONS = frozenset({".bst"})
_XGBOOST_PICKLE_SPOOF_REASON = "xgboost_binary_pickle_spoof"
_RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON = "recognized_format_scanner_unavailable"
_XML_MODEL_ROUTING_INCOMPLETE_REASON = "xml_model_routing_incomplete"
_ShardFamilyKey = tuple[str, str, int | None]
_ScanEntry = tuple[str, list[str], _ShardFamilyKey | None]
_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY = "shard_family_cache_fingerprint"


def _start_phase_timing(phase_timings: dict[str, float] | None) -> float | None:
    return time.perf_counter() if phase_timings is not None else None


def _finish_phase_timing(
    phase_timings: dict[str, float] | None,
    phase_name: str,
    started_at: float | None,
) -> None:
    if phase_timings is None or started_at is None:
        return
    phase_timings[phase_name] = phase_timings.get(phase_name, 0.0) + (time.perf_counter() - started_at)


def _attach_phase_timings(results: ModelAuditResultModel, phase_timings: dict[str, float] | None) -> None:
    if phase_timings is not None:
        results.phase_timings = phase_timings  # type: ignore[attr-defined]


def _shard_family_key_for_path(path: str) -> _ShardFamilyKey | None:
    """Return a stable key for files that belong to the same local shard family."""
    path_obj = Path(path)
    shard_match = ShardedModelDetector.match_shard_filename(path_obj.name)
    if shard_match is None:
        return None

    pattern = shard_match.get("pattern")
    if not isinstance(pattern, str):
        return None

    expected_total = shard_match.get("expected_total_shards")
    if not isinstance(expected_total, int):
        expected_total = None

    return (str(path_obj.parent), pattern, expected_total)


def _build_shard_family_cache_fingerprint(
    shard_family_key: _ShardFamilyKey,
    scanned_file_paths: list[str],
    content_hashes: dict[str, str],
) -> dict[str, Any]:
    """Fingerprint every present shard so representative cache entries stay valid."""
    _parent_dir, pattern, expected_total_shards = shard_family_key
    return {
        "pattern": pattern,
        "expected_total_shards": expected_total_shards,
        "members": [
            {
                "path": str(Path(scanned_file_path).resolve()),
                "content_hash": content_hashes.get(scanned_file_path),
            }
            for scanned_file_path in sorted(scanned_file_paths)
        ],
    }


def _allowed_shard_paths_from_config(config: dict[str, Any]) -> list[str] | None:
    """Return validated shard paths embedded in a grouped directory-scan config."""
    fingerprint = config.get(_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY)
    if not isinstance(fingerprint, dict):
        return None

    members = fingerprint.get("members")
    if not isinstance(members, list):
        return None

    allowed_paths = [
        str(member["path"]) for member in members if isinstance(member, dict) and isinstance(member.get("path"), str)
    ]
    return allowed_paths or None


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
        return "zip"

    if ext == ".joblib" and header_format in _COMPRESSED_HEADER_FORMATS | {"pickle"}:
        return "joblib"

    if ext in _R_SERIALIZED_EXTENSIONS and header_format in _COMPRESSED_HEADER_FORMATS | {"r_serialized"}:
        return "r_serialized"

    if header_format == "tar" and ext == ".nemo":
        return "nemo"

    return _registry.get_scanner_id_for_header_format(header_format)


def _is_direct_header_route(scanner_id: str, header_format: str) -> bool:
    """Return whether the detected header directly maps to this scanner."""
    return header_format != "unknown" and HEADER_FORMAT_TO_SCANNER_ID.get(header_format) == scanner_id


def _preferred_scanner_can_handle(
    scanner_class: type[BaseScanner],
    scanner_id: str,
    header_format: str,
    path: str,
) -> bool:
    """Honor trusted header routing even when scanner can_handle is suffix-gated."""
    if scanner_class.can_handle(path):
        return True

    if os.path.exists(path) and _is_direct_header_route(scanner_id, header_format):
        logger.debug(
            "Using %s scanner for %s based on detected %s header despite can_handle rejection",
            scanner_class.name,
            path,
            header_format,
        )
        return True

    return False


def _mark_xgboost_pickle_extension_spoof(result: ScanResult, path: str, ext: str) -> None:
    """Preserve pickle analysis while flagging XGBoost extension spoofing."""
    existing_reasons = result.metadata.get("scan_outcome_reasons")
    if isinstance(existing_reasons, list) and _XGBOOST_PICKLE_SPOOF_REASON in existing_reasons:
        result.success = False
        return

    claimed_format = ext.lower().lstrip(".") or "binary"
    result.add_check(
        name="File Format Validation",
        passed=False,
        message=f"File appears to be a pickle file with .{claimed_format} extension",
        severity=IssueSeverity.WARNING,
        location=path,
        details={"detected_format": "pickle", "claimed_format": claimed_format},
        why=(
            "File extension spoofing is a security evasion technique used to bypass security scanners. "
            "This may indicate malicious intent."
        ),
    )
    _mark_inconclusive_scan_outcome(result, _XGBOOST_PICKLE_SPOOF_REASON)
    result.success = False


def _make_unavailable_recognized_format_result(path: str, format_: str, scanner_id: str | None) -> ScanResult:
    """Fail closed when routing recognizes a format but no scanner can analyze it."""
    result = ScanResult(scanner_name="unknown")
    details: dict[str, Any] = {"format": format_, "path": path}
    if scanner_id:
        details["preferred_scanner_id"] = scanner_id
        scanner_load_error = _registry.get_failed_scanners().get(scanner_id)
        if scanner_load_error:
            details["scanner_load_error"] = scanner_load_error

    result.add_check(
        name="Format Detection",
        passed=False,
        message="Recognized format could not be scanned because no scanner was available",
        severity=IssueSeverity.INFO,
        location=path,
        details=details,
    )
    _mark_inconclusive_scan_outcome(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
    _mark_operational_scan_error(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_xml_model_result(path: str) -> ScanResult:
    """Fail closed when bounded XML routing cannot reach the structural root."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="XML Model Routing",
        passed=False,
        message=(
            "XML model routing was inconclusive because the bounded probe ended "
            "before the first structural root element"
        ),
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": XML_MODEL_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _XML_MODEL_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _XML_MODEL_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


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


def _hash_files_by_path(file_paths: list[str]) -> dict[str, str]:
    """Hash files individually so scan results stay path-specific.

    Args:
        file_paths: List of file paths to group

    Returns:
        Dictionary mapping each file path to its content hash. Files that fail to
        hash get unique placeholder values so they still scan independently.
    """
    content_hashes: dict[str, str] = {}
    hashes_by_inode: dict[tuple[int, int, int, int], str] = {}

    for file_path in file_paths:
        try:
            inode_key: tuple[int, int, int, int] | None = None
            try:
                file_stat = os.stat(file_path)
                if file_stat.st_nlink > 1:
                    inode_key = (
                        file_stat.st_dev,
                        file_stat.st_ino,
                        file_stat.st_size,
                        file_stat.st_mtime_ns,
                    )
                    if cached_hash := hashes_by_inode.get(inode_key):
                        content_hashes[file_path] = cached_hash
                        continue
            except OSError:
                # Fall back to direct hashing when stat is unavailable or the file changes mid-scan.
                pass

            content_hashes[file_path] = _calculate_file_hash(file_path)
            if inode_key is not None:
                hashes_by_inode[inode_key] = content_hashes[file_path]
        except Exception as e:
            # Log error but continue with other files to prevent single I/O failure from aborting entire scan
            logger.warning(f"Failed to hash file {file_path}: {e}. Skipping deduplication for this file.")
            content_hashes[file_path] = f"unhashable_{id(file_path)}"

    return content_hashes


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
    nearby_license_cache: dict[str, list[str]] = {}

    phase_timings: dict[str, float] | None = {} if bool(kwargs.get("profile_timings")) else None

    # Configure scan options
    scanner_selection_started_at = _start_phase_timing(phase_timings)
    config = {
        "blacklist_patterns": blacklist_patterns,
        "max_file_size": max_file_size,
        "max_total_size": max_total_size,
        "timeout": timeout,
        "skip_file_types": skip_file_types,
        "strict_license": strict_license,
        **kwargs,
    }
    config = normalize_scanner_selection_config(config)
    scanner_selection = policy_from_config(config)
    scanner_selection_extensions = selected_scanner_extensions(scanner_selection) if scanner_selection.active else None
    if scanner_selection.active:
        results.scanner_selection = scanner_selection.to_metadata()

    validate_scan_config(config)
    _finish_phase_timing(phase_timings, "scanner_selection", scanner_selection_started_at)

    # Check if metadata scanner is available once (optimization - avoids loading scanner)
    metadata_scanner_available = scanner_selection.allows("metadata") and _registry.has_scanner_class("MetadataScanner")

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
                scan_result, analysis_complete = stream_analyze_file(stream_url, scanner)
                if scan_result:
                    if not analysis_complete:
                        _mark_inconclusive_scan_outcome(scan_result, "streaming_analysis_incomplete")
                    results.files_scanned += 1

                    # Use helper function to add scan result to Pydantic model
                    _add_scan_result_to_model(results, scan_metadata, scan_result, stream_url)

                    # Add asset
                    _add_asset_to_results(results, stream_url, scan_result)

                    if not analysis_complete:
                        _add_issue_to_model(
                            results,
                            "Streaming analysis incomplete - full scanner coverage was not available",
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
                streaming_scan_started_at = _start_phase_timing(phase_timings)
                _consolidate_checks(results)
                _finish_phase_timing(phase_timings, "result_consolidation", streaming_scan_started_at)
            except Exception as e:
                logger.warning(f"Error consolidating checks ({type(e).__name__}): {e!s}", exc_info=e)
            results.has_errors = bool(scan_metadata.get("has_operational_errors", False))
            results.success = not _results_should_be_unsuccessful(results)
            results.finalize_statistics()
            _attach_phase_timings(results, phase_timings)
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

            # Scan all files in the directory. File counts are only needed for
            # progress percentages, so avoid the extra tree walk when callers do
            # not request progress updates.
            total_files = None  # Will be set to actual count if directory is small
            processed_files = 0
            limit_reached = False

            if progress_callback:
                # Quick check: count files only if directory seems reasonable in size.
                # This avoids the expensive rglob() on large directories.
                try:
                    directory_file_count_started_at = _start_phase_timing(phase_timings)
                    # Do a quick count of immediate children first.
                    immediate_children = _count_immediate_children_up_to(
                        Path(path),
                        _DIRECTORY_PRECOUNT_CHILD_LIMIT,
                    )
                    # Only run the recursive count for narrower roots.
                    if immediate_children < _DIRECTORY_PRECOUNT_CHILD_LIMIT:
                        total_files = _count_files_up_to(Path(path), _DIRECTORY_PRECOUNT_CHILD_LIMIT)
                except (OSError, PermissionError):
                    # If we can't count, just proceed without progress percentage.
                    total_files = None
                finally:
                    _finish_phase_timing(phase_timings, "directory_file_count", directory_file_count_started_at)

            base_dir = Path(path).resolve()
            hf_cache_root = _find_hf_cache_root(base_dir)
            is_hf_cache = hf_cache_root is not None
            scanned_paths: set[str] = set()

            # First pass: collect all file paths that need scanning
            files_to_scan: list[str] = []
            shard_family_representatives: dict[_ShardFamilyKey, str] = {}
            shard_family_paths: dict[_ShardFamilyKey, set[str]] = {}
            directory_discovery_started_at = _start_phase_timing(phase_timings)
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
                        file_path,
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_extensions,
                    ):
                        filename_lower = Path(file_path).name.lower()
                        if filename_lower in LICENSE_FILES:
                            try:
                                license_metadata_started_at = _start_phase_timing(phase_timings)
                                try:
                                    license_metadata = collect_license_metadata(
                                        str(resolved_file),
                                        nearby_license_cache=nearby_license_cache,
                                    )
                                finally:
                                    _finish_phase_timing(phase_timings, "license_metadata", license_metadata_started_at)
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
                        shard_family_key = _shard_family_key_for_path(target_str)
                        if shard_family_key is not None:
                            family_paths = shard_family_paths.setdefault(shard_family_key, set())
                            family_paths.add(target_str)
                            if shard_family_key not in shard_family_representatives:
                                shard_family_representatives[shard_family_key] = target_str
                                shard_info = ShardedModelDetector.detect_shards(target_str)
                                if shard_info is not None:
                                    for shard_path in shard_info.get("shards", []):
                                        if isinstance(shard_path, str):
                                            resolved_shard_path = str(Path(shard_path).resolve())
                                            shard_in_base_dir = is_within_directory(str(base_dir), resolved_shard_path)
                                            shard_in_hf_blobs = bool(
                                                is_hf_cache
                                                and hf_cache_root is not None
                                                and is_within_directory(
                                                    str(hf_cache_root / "blobs"),
                                                    resolved_shard_path,
                                                )
                                            )
                                            if shard_in_base_dir or shard_in_hf_blobs:
                                                family_paths.add(resolved_shard_path)
                                            else:
                                                _add_issue_to_model(
                                                    results,
                                                    "Path traversal outside scanned directory",
                                                    severity=IssueSeverity.CRITICAL.value,
                                                    location=resolved_shard_path,
                                                    details={"resolved_path": resolved_shard_path},
                                                )
                            continue

                        files_to_scan.append(target_str)
            _finish_phase_timing(phase_timings, "directory_discovery", directory_discovery_started_at)

            scan_entries: list[_ScanEntry] = [(file_path, [file_path], None) for file_path in files_to_scan]
            for shard_family_key, representative_file in shard_family_representatives.items():
                ordered_family_paths = sorted(shard_family_paths.get(shard_family_key, {representative_file}))
                scan_entries.append((representative_file, ordered_family_paths, shard_family_key))

            # Second pass: scan every non-shard path independently and every shard
            # family once. Shard scans already expand to sibling shards in the
            # advanced handler, so scanning each shard path would duplicate work.
            if scan_entries:
                hash_paths: list[str] = []
                seen_hash_paths: set[str] = set()
                for _representative_file, scanned_file_paths, _shard_family_key in scan_entries:
                    for scanned_file_path in scanned_file_paths:
                        if scanned_file_path not in seen_hash_paths:
                            hash_paths.append(scanned_file_path)
                            seen_hash_paths.add(scanned_file_path)

                top_level_hashing_started_at = _start_phase_timing(phase_timings)
                content_hashes = _hash_files_by_path(hash_paths)
                _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)
                duplicate_paths_by_hash: dict[str, list[str]] = {}
                for file_path, content_hash in content_hashes.items():
                    if not content_hash.startswith("unhashable_"):
                        duplicate_paths_by_hash.setdefault(content_hash, []).append(file_path)
                recorded_content_hashes: set[str] = set()

                for representative_file, scanned_file_paths, shard_family_key in scan_entries:
                    # Check for interrupts
                    check_interrupted()

                    # Check timeout
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Scan timeout after {timeout} seconds")

                    # Update progress
                    if progress_callback:
                        scan_label = Path(representative_file).name
                        if len(scanned_file_paths) > 1:
                            scan_label = f"{scan_label} ({len(scanned_file_paths)} shards)"
                        if total_files is not None and total_files > 0:
                            progress_callback(
                                f"Scanning file {processed_files + 1}/{total_files}: {scan_label}",
                                processed_files / total_files * 100,
                            )
                        else:
                            progress_callback(
                                f"Scanning file {processed_files + 1}: {scan_label}",
                                0.0,
                            )

                    try:
                        # Check for interrupts before scanning each file
                        check_interrupted()

                        file_scan_started_at = _start_phase_timing(phase_timings)
                        try:
                            file_config = config
                            if shard_family_key is not None:
                                file_config = dict(config)
                                file_config[_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY] = (
                                    _build_shard_family_cache_fingerprint(
                                        shard_family_key,
                                        scanned_file_paths,
                                        content_hashes,
                                    )
                                )
                            file_result = scan_file(representative_file, file_config)
                        finally:
                            _finish_phase_timing(phase_timings, "file_scan_dispatch", file_scan_started_at)

                        result_merge_started_at = _start_phase_timing(phase_timings)
                        _normalize_unclassified_scan_failure(file_result)
                        if _scan_result_has_operational_error(file_result):
                            scan_metadata["has_operational_errors"] = True
                        results.bytes_scanned += file_result.bytes_scanned
                        results.files_scanned += len(scanned_file_paths)
                        processed_files += len(scanned_file_paths)
                        for scanned_file_path in scanned_file_paths:
                            path_content_hash = content_hashes.get(scanned_file_path)
                            if (
                                path_content_hash is not None
                                and not path_content_hash.startswith("unhashable_")
                                and path_content_hash not in recorded_content_hashes
                            ):
                                file_hashes.append(path_content_hash)
                                recorded_content_hashes.add(path_content_hash)

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

                        # Add issues from this path-specific scan using Pydantic models
                        for issue in file_result.issues:
                            issue_dict = issue.to_dict() if hasattr(issue, "to_dict") else issue
                            if isinstance(issue_dict, dict):
                                issue_details = issue_dict.get("details")
                                issue_details = issue_details if isinstance(issue_details, dict) else {}
                                record_issue_found(
                                    issue_type=str(issue_dict.get("type") or "unknown_issue"),
                                    severity=_to_telemetry_severity(issue_dict.get("severity", "unknown")),
                                    scanner=file_result.scanner_name,
                                    file_path=representative_file,
                                    rule_code=(
                                        issue_dict.get("rule_code")
                                        if isinstance(issue_dict.get("rule_code"), str)
                                        else None
                                    ),
                                    cve_id=(
                                        issue_details.get("cve_id")
                                        if isinstance(issue_details.get("cve_id"), str)
                                        else None
                                    ),
                                    issue_message=(
                                        issue_dict.get("message")
                                        if isinstance(issue_dict.get("message"), str)
                                        else None
                                    ),
                                )
                                if not issue_dict.get("location"):
                                    issue_dict["location"] = representative_file

                                # Ensure timestamp is present
                                if "timestamp" not in issue_dict:
                                    issue_dict["timestamp"] = time.time()

                                results.issues.append(Issue(**issue_dict))

                        # Add checks from this path-specific scan using Pydantic models
                        if hasattr(file_result, "checks"):
                            from .models import Check

                            for check in file_result.checks:
                                check_dict = check.to_dict() if hasattr(check, "to_dict") else check
                                if isinstance(check_dict, dict):
                                    if not check_dict.get("location"):
                                        check_dict["location"] = representative_file

                                    # Ensure timestamp is present
                                    if "timestamp" not in check_dict:
                                        check_dict["timestamp"] = time.time()

                                    results.checks.append(Check(**check_dict))

                        # Add metadata for this path using Pydantic models
                        from .models import FileMetadataModel

                        for scanned_file_path in scanned_file_paths:
                            license_metadata_started_at = _start_phase_timing(phase_timings)
                            try:
                                license_metadata = collect_license_metadata(
                                    scanned_file_path,
                                    nearby_license_cache=nearby_license_cache,
                                )
                            finally:
                                _finish_phase_timing(phase_timings, "license_metadata", license_metadata_started_at)
                            combined_metadata = {**file_result.metadata, **license_metadata}
                            if len(scanned_file_paths) > 1 and "file_size" in combined_metadata:
                                with suppress(OSError):
                                    combined_metadata["file_size"] = os.path.getsize(scanned_file_path)
                            path_content_hash = content_hashes.get(scanned_file_path)
                            if path_content_hash is not None:
                                combined_metadata["content_hash"] = path_content_hash
                                duplicate_files = duplicate_paths_by_hash.get(path_content_hash, [])
                                combined_metadata["duplicate_files"] = (
                                    duplicate_files if len(duplicate_files) > 1 else None
                                )

                            # Convert ml_context if present
                            if "ml_context" in combined_metadata and isinstance(combined_metadata["ml_context"], dict):
                                from .models import MLContextModel

                                combined_metadata["ml_context"] = MLContextModel(**combined_metadata["ml_context"])

                            _add_asset_to_results(
                                results,
                                scanned_file_path,
                                file_result,
                                metadata=combined_metadata,
                            )
                            results.file_metadata[scanned_file_path] = FileMetadataModel(**combined_metadata)
                        _finish_phase_timing(phase_timings, "result_merge", result_merge_started_at)

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

                        _add_issue_to_model(
                            results,
                            f"Error scanning file: {e!s}",
                            severity=IssueSeverity.INFO.value,
                            location=representative_file,
                            details={"exception_type": type(e).__name__},
                        )
                        for scanned_file_path in scanned_file_paths:
                            _add_error_asset_to_results(results, scanned_file_path)

            # Final progress update for directory scan
            if progress_callback and not limit_reached and total_files is not None and total_files > 0:
                progress_callback(
                    f"Completed scanning {processed_files} files",
                    100.0,
                )
            # Stop scanning if size limit reached
            if limit_reached:
                logger.warning("Scan terminated early due to total size limit")
                scan_metadata["success"] = False
                scan_metadata["has_operational_errors"] = True
                _add_issue_to_model(
                    results,
                    "Scan terminated early due to total size limit",
                    severity=IssueSeverity.INFO.value,
                    location=path,
                    details={"max_total_size": max_total_size, "analysis_incomplete": True},
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

                # Hash the top-level target before scanning. Archive scanners merge
                # nested member results into their metadata, so scanner-emitted
                # hashes are not always the bytes of this target.
                try:
                    top_level_hashing_started_at = _start_phase_timing(phase_timings)
                    file_hash = _calculate_file_hash(target)
                    file_hashes.append(file_hash)
                except Exception as e:
                    logger.debug(f"Failed to hash file {target}: {e}")
                finally:
                    _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)

                file_scan_started_at = _start_phase_timing(phase_timings)
                try:
                    file_result = scan_file(target, config)
                finally:
                    _finish_phase_timing(phase_timings, "file_scan_dispatch", file_scan_started_at)

                # Use helper function to add scan result to Pydantic model
                result_merge_started_at = _start_phase_timing(phase_timings)
                _add_scan_result_to_model(results, scan_metadata, file_result, target)

                _add_asset_to_results(results, target, file_result)
                _finish_phase_timing(phase_timings, "result_merge", result_merge_started_at)

                # Collect and apply license metadata for all files
                license_metadata_started_at = _start_phase_timing(phase_timings)
                try:
                    license_metadata = collect_license_metadata(
                        target,
                        nearby_license_cache=nearby_license_cache,
                    )
                finally:
                    _finish_phase_timing(phase_timings, "license_metadata", license_metadata_started_at)
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
        result_consolidation_started_at = _start_phase_timing(phase_timings)
        _consolidate_checks(results)
        _finish_phase_timing(phase_timings, "result_consolidation", result_consolidation_started_at)
    except Exception as e:
        logger.warning(f"Error consolidating checks ({type(e).__name__}): {e!s}", exc_info=e)

    # Add license warnings if any
    try:
        commercial_use_started_at = _start_phase_timing(phase_timings)
        license_warnings = check_commercial_use_warnings(results, strict=config.get("strict_license", False))
        _finish_phase_timing(phase_timings, "commercial_use_warnings", commercial_use_started_at)
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

        aggregate_hash_started_at = _start_phase_timing(phase_timings)
        results.content_hash = compute_aggregate_hash(file_hashes)
        _finish_phase_timing(phase_timings, "aggregate_hash", aggregate_hash_started_at)
        logger.info(f"Computed aggregate content hash from {len(file_hashes)} file(s): {results.content_hash}")

    # Finalize statistics and return Pydantic model
    results.finalize_statistics()
    results.deduplicate_issues()
    _attach_phase_timings(results, phase_timings)
    return results


# _should_skip_file has been moved to utils.file_filter module


def _is_hf_hub_bookkeeping_path(path_obj: Path) -> bool:
    """Return True for files stored under known HuggingFace hub bookkeeping directories."""
    hf_cache_root = _find_hf_cache_root(path_obj)
    if hf_cache_root is None:
        return False

    try:
        relative_parts = _resolve_hf_cache_path(path_obj).relative_to(hf_cache_root).parts
    except ValueError:
        return False

    return bool(relative_parts and relative_parts[0] in {"snapshots", "blobs", "refs"})


def _is_hf_download_bookkeeping_path(path_obj: Path) -> bool:
    """Return True for files stored in HuggingFace download bookkeeping directories."""
    import os

    resolved_parent = _resolve_hf_cache_path(path_obj.parent)
    configured_download_roots = {
        _resolve_hf_cache_path(root.parent / "download")
        for root in _get_hf_cache_roots()
        if root.parent.name.lower() == "huggingface"
    }
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        configured_download_roots.add(_resolve_hf_cache_path(Path(hf_home) / "download"))
    if resolved_parent in configured_download_roots:
        return True

    # Local snapshot downloads keep bookkeeping under the downloaded model
    # directory rather than the global cache root.
    parts = resolved_parent.parts
    if len(parts) < 3 or tuple(part.lower() for part in parts[-3:]) != (".cache", "huggingface", "download"):
        return False

    local_model_root = resolved_parent.parents[2]
    try:
        has_local_model_assets = any(child.is_file() for child in local_model_root.iterdir() if child.name != ".cache")
    except OSError:
        return False
    return has_local_model_assets and _is_benign_local_hf_download_bookkeeping_file(path_obj)


def _is_benign_local_hf_download_bookkeeping_file(path_obj: Path) -> bool:
    """Return True only for local download bookkeeping files that do not look scannable."""
    import json

    filename = path_obj.name
    try:
        if detect_file_format(str(path_obj)) != "unknown":
            return False
        if filename.endswith(".lock"):
            return path_obj.stat().st_size == 0
        if filename.endswith(".metadata"):
            with path_obj.open(encoding="utf-8") as handle:
                return isinstance(json.load(handle), dict)
        if filename in {".gitignore", ".gitattributes"}:
            content = path_obj.read_text(encoding="utf-8")
            return "\x00" not in content and len(content) <= 64 * 1024
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return False


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
    if not (filename.endswith((".lock", ".metadata")) or filename in {".gitignore", ".gitattributes", "main", "HEAD"}):
        return False

    # Only trust bookkeeping-shaped filenames when they actually live in a
    # recognized HuggingFace cache layout.
    path_obj = Path(path)

    if filename in ["main", "HEAD"]:
        hf_cache_root = _find_hf_cache_root(path_obj)
        if hf_cache_root is None:
            return False

        try:
            relative_parts = _resolve_hf_cache_path(path_obj).relative_to(hf_cache_root).parts
        except ValueError:
            return False

        return bool(relative_parts and relative_parts[0] == "refs")

    is_hf_bookkeeping_path = _is_hf_hub_bookkeeping_path(path_obj) or _is_hf_download_bookkeeping_path(path_obj)
    if filename.endswith((".lock", ".metadata")):
        return is_hf_bookkeeping_path

    # Check for specific HuggingFace cache metadata files
    # We no longer skip all HuggingFace cache files since we handle symlinks properly now

    # Check for Git-related files that are commonly cached
    if filename in [".gitignore", ".gitattributes"]:
        return is_hf_bookkeeping_path

    return False


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
    config = normalize_scanner_selection_config({} if config is None else dict(config))
    config.setdefault(NESTED_SCAN_CALLBACK_CONFIG_KEY, scan_file)
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
    config = normalize_scanner_selection_config(config)
    scanner_selection = policy_from_config(config)
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
    is_xgboost_pickle_spoof = ext in _XGBOOST_BINARY_EXTENSIONS and header_format == "pickle"

    # Record telemetry for file type detection
    detected_format = header_format if header_format != "unknown" else ext_format
    record_file_type_detected(path, detected_format)

    # Validate file type consistency as a security check
    magic_format = detect_file_format_from_magic(path)
    file_type_valid = validate_file_type_with_formats(path, magic_format, ext_format)
    discrepancy_msg = None

    if not file_type_valid:
        # File type validation failed - this is a security concern
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
            or (ext_format == "protobuf" and header_format == "onnx" and ext == ".pb")
            or (ext_format == "skops" and header_format == "zip" and ext == ".skops")
        ):
            discrepancy_msg = f"File extension indicates {ext_format} but header indicates {header_format}."
            logger.debug(discrepancy_msg)

    # Prefer scanners based on trusted structure rather than the filename alone.
    preferred_scanner: type[BaseScanner] | None = None
    scanner_id = _select_preferred_scanner_id(path, header_format, ext)
    skipped_preferred_scanner_id: str | None = None
    if scanner_id and scanner_selection.allows(scanner_id):
        preferred_scanner = _registry.load_scanner_by_id(scanner_id)
    elif scanner_id:
        skipped_preferred_scanner_id = scanner_id

    result: ScanResult | None

    # We already checked use_extreme_handler above for size limit bypass
    # Now check if we should use regular large handler
    use_large_handler = should_use_large_file_handler(path) and not use_extreme_handler
    progress_callback = config.get("progress_callback")
    timeout = config.get("timeout", 3600)
    config[FORMAT_VALIDATION_CONFIG_KEY] = {
        "path": os.path.abspath(path),
        "header_format": magic_format,
        "extension_format": ext_format,
        "file_type_valid": file_type_valid,
    }

    if (
        preferred_scanner
        and scanner_id
        and _preferred_scanner_can_handle(preferred_scanner, scanner_id, header_format, path)
    ):
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
                    path,
                    scanner,
                    progress_callback,
                    timeout * 2,
                    allowed_shard_paths=_allowed_shard_paths_from_config(config),
                )  # Double timeout for extreme files
            elif use_large_handler:
                logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                result = scan_large_file(path, scanner, progress_callback, timeout)
            elif is_xgboost_pickle_spoof:
                result = scanner.scan(path)
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
        scanner_class = _registry.get_scanner_for_path(
            path,
            scanner_selection=scanner_selection if scanner_selection.active else None,
        )
        if scanner_class:
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner = scanner_class(config=config)

            try:
                # Record scanner usage telemetry
                scan_start = time.time()

                if use_extreme_handler:
                    logger.debug(f"Large file optimization enabled: {path}")
                    result = scan_advanced_large_file(
                        path,
                        scanner,
                        progress_callback,
                        timeout * 2,
                        allowed_shard_paths=_allowed_shard_paths_from_config(config),
                    )  # Double timeout for extreme files
                elif use_large_handler:
                    logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                    result = scan_large_file(path, scanner, progress_callback, timeout)
                elif is_xgboost_pickle_spoof:
                    result = scanner.scan(path)
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
            if skipped_preferred_scanner_id and result is not None:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    skipped_preferred_scanner_id,
                    scanner_selection,
                    context="preferred scanner",
                    kind=SCANNER_SELECTION_PREFERRED_KIND,
                )
        else:
            if scanner_selection.active:
                candidate_scanner_id = skipped_preferred_scanner_id
                if candidate_scanner_id is None:
                    candidate_scanner_class = _registry.get_scanner_for_path(path)
                    if candidate_scanner_class:
                        candidate_scanner_id = (
                            _registry.get_scanner_id_for_class(candidate_scanner_class.__name__)
                            or candidate_scanner_class.name
                        )
                if candidate_scanner_id and not scanner_selection.allows(candidate_scanner_id):
                    result = make_scanner_selection_skip_result(path, candidate_scanner_id, scanner_selection)
                    if result.bytes_scanned == 0 and file_size > 0:
                        result.bytes_scanned = file_size
                    return result

            if magic_format == XML_MODEL_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_xml_model_result(path)
            elif magic_format == "unknown":
                # Not a recognized model format — skip silently
                sr = ScanResult(scanner_name="unknown")
                logger.debug(f"Skipping unrecognized format file: {path}")
            else:
                sr = _make_unavailable_recognized_format_result(path, magic_format, scanner_id)
            result = sr

    if is_xgboost_pickle_spoof:
        _mark_xgboost_pickle_extension_spoof(result, path, ext)

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
    skip_file_types: bool = bool(kwargs.get("skip_file_types", False))
    scan_kwargs = normalize_scanner_selection_config(kwargs)
    scanner_selection = policy_from_config(scan_kwargs)
    scanner_selection_extensions = selected_scanner_extensions(scanner_selection) if scanner_selection.active else None
    if scanner_selection.active:
        results.scanner_selection = scanner_selection.to_metadata()
    metadata_scanner_available: bool = scanner_selection.allows("metadata") and _registry.has_scanner_class(
        "MetadataScanner"
    )
    nearby_license_cache: dict[str, list[str]] = {}

    base_dir = Path(scan_root).resolve() if scan_root is not None else None
    hf_cache_root = _find_hf_cache_root(base_dir) if base_dir is not None else None
    is_hf_cache = base_dir is not None and hf_cache_root is not None

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
                if is_hf_cache and _is_huggingface_cache_file(str(source_path)):
                    logger.debug(f"Skipping HuggingFace cache file: {source_path}")
                    continue

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

                if skip_file_types and should_skip_file(
                    str(source_path),
                    metadata_scanner_available=metadata_scanner_available,
                    scanner_selection_extensions=scanner_selection_extensions,
                ):
                    filename_lower = source_path.name.lower()
                    if filename_lower in LICENSE_FILES:
                        try:
                            license_metadata = collect_license_metadata(
                                str(scan_path),
                                nearby_license_cache=nearby_license_cache,
                            )
                            from .models import FileMetadataModel

                            results.file_metadata[report_path] = FileMetadataModel(**license_metadata)
                            logger.debug(f"Collected license metadata from skipped file: {source_path}")
                        except Exception as e:
                            logger.warning(f"Error collecting license metadata for {source_path}: {e}")
                    else:
                        logger.debug(f"Skipping non-model file: {source_path}")
                    continue

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
                    **scan_kwargs,
                }

                scan_result = scan_file(
                    str(scan_path),
                    config=scan_config,
                )

                # Merge results
                if scan_result:
                    _normalize_unclassified_scan_failure(scan_result)
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
                        # Bare success=False results were normalized above so
                        # they fail closed as inconclusive instead of exiting 0.
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
