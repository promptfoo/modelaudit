"""Core scanning engine for orchestrating model file security analysis."""

import hashlib
import itertools
import json
import logging
import math
import os
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import AnyUrl, BaseModel

try:
    from modelaudit_picklescan import shared_source_sensitive_caches
except ImportError:

    @contextmanager
    def shared_source_sensitive_caches() -> Iterator[None]:
        """Preserve compatibility with older independently versioned picklescan installs."""
        yield


import modelaudit.core_results as core_results
from modelaudit.integrations.license_checker import (
    LICENSE_FILES,
    check_commercial_use_warnings,
    collect_license_metadata,
)
from modelaudit.models import ModelAuditResultModel, ScanConfigModel, create_initial_audit_result
from modelaudit.scanner_results import (
    ACTIONABLE_FAILED_CHECKS_METADATA_KEY,
    INCONCLUSIVE_SCAN_OUTCOME,
    OPERATIONAL_ERROR_METADATA_KEY,
    SCAN_OUTCOME_METADATA_KEY,
    SCAN_OUTCOME_REASONS_METADATA_KEY,
    SUPPRESSED_FAILED_CHECKS_METADATA_KEY,
    VALIDATED_FORMAT_METADATA_KEY,
    Check,
    CheckStatus,
    Issue,
    IssueSeverity,
    ScanResult,
)
from modelaudit.scanner_selection import (
    SCANNER_SELECTION_PREFERRED_KIND,
    ScannerSelectionPolicy,
    add_scanner_selection_skip_check,
    allows_protobuf_model_candidate_analysis,
    allows_zip_content_analysis,
    allows_zip_structure_analysis,
    make_scanner_selection_skip_result,
    normalize_scanner_selection_config,
    policy_from_config,
    selected_scanner_extensions,
)
from modelaudit.scanners import _registry
from modelaudit.scanners.archive_dispatch import (
    NESTED_SCAN_CALLBACK_CONFIG_KEY,
    detect_safetensors_overlap_scanner_ids,
    merge_executable_zip_container_findings,
    merge_flax_msgpack_overlap_findings,
    merge_hdf5_userblock_zip_findings,
    merge_inconclusive_flax_msgpack_outcome,
    merge_safetensors_overlap_analysis,
)
from modelaudit.scanners.base import (
    DEFAULT_MAX_FILE_READ_SIZE,
    FORMAT_VALIDATION_CONFIG_KEY,
    BaseScanner,
    _trusted_logical_scan_path,
)
from modelaudit.scanners.jax_checkpoint_scanner import JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY
from modelaudit.scanners.mxnet_scanner import MXNET_PREFERRED_XGBOOST_SKIP_PATH_CONFIG_KEY
from modelaudit.scanners.safetensors_scanner import MAX_HEADER_BYTES as SAFETENSORS_MAX_HEADER_BYTES
from modelaudit.scanners.xgboost_scanner import (
    XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY,
    XGBoostScanner,
    configure_content_routed_json_scan,
)
from modelaudit.telemetry import record_file_type_detected, record_issue_found, record_scanner_used
from modelaudit.utils import (
    DVC_ANALYSIS_INCOMPLETE_REASON,
    DvcResolution,
    dvc_omitted_outputs_covered,
    is_within_directory,
    resolve_dvc_file_status,
    should_skip_file,
)
from modelaudit.utils.file.detection import (
    EXECUTABLE_ZIP_POLYGLOT_FORMAT,
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_SIGNATURE_READ_BYTES,
    NEMO_ROUTING_INCONCLUSIVE_FORMAT,
    ONNX_ROUTING_INCONCLUSIVE_FORMAT,
    PICKLE_ROUTING_INCONCLUSIVE_FORMAT,
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT,
    TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
    VALIDATED_DESCRIPTOR_BOUND_SOURCE_CONFIG_KEY,
    XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
    XML_MODEL_INCONCLUSIVE_FORMAT,
    _is_malformed_sentencepiece_model_proto_candidate_file,
    _is_private_descriptor_bound_regular_file,
    detect_file_format,
    detect_file_format_for_skip_filter,
    detect_file_format_from_magic,
    detect_flax_msgpack_overlap_routes,
    detect_format_from_extension,
    detect_mxnet_symbol_content_route,
    detect_pytorch_binary_supplemental_format,
    detect_xgboost_ubjson_content_route,
    gzip_tar_trailing_data_status,
    huggingface_tokenizer_json_has_jax_route_evidence,
    huggingface_tokenizer_json_has_template_route_evidence,
    is_confirmed_jax_json_checkpoint_file,
    is_executorch_archive,
    is_huggingface_tokenizer_json_file,
    is_jax_json_checkpoint_file,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_sentencepiece_model_proto_file,
    is_skops_archive,
    is_torchserve_mar_archive,
    should_defer_safetensors_header_limit_hash,
    validate_file_type_with_formats,
)
from modelaudit.utils.file.handlers import (
    _DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY,
    _PREVALIDATED_SHARD_INFO_CONFIG_KEY,
    _SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY,
    _SHARD_ALREADY_PINNED_CONFIG_KEY,
    CONTEXT_ONLY_COMPANION_TARGET_KEY,
    MAX_RECORDED_MISSING_SHARD_INDICES,
    MAX_SAFETENSORS_SHARD_INDEX_BYTES,
    MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES,
    MAX_SAFETENSORS_SHARD_INDEX_FILES,
    MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES,
    SAFETENSORS_INDEX_SUFFIX,
    ShardedModelDetector,
    ValidatedShardTargets,
    _activate_safetensors_index_inspection_context,
    _count_expected_shard_indices,
    _deactivate_safetensors_index_inspection_context,
    _load_safetensors_index_json,
    _open_windows_shard_guard_fd,
    _pinned_shard_scan_path,
    _preserve_findings_with_shard_boundary_failure,
    _rebase_pinned_shard_result,
    _SafetensorsIndexInspectionContext,
    _ShardPinUnavailableError,
    _StagingMutationMonitor,
    _validated_stat_matches_target,
    scan_advanced_large_file,
    should_use_advanced_handler,
)
from modelaudit.utils.file.hdf5 import find_hdf5_signature_offset
from modelaudit.utils.file.large_file_handler import (
    scan_large_file,
    should_use_large_file_handler,
)
from modelaudit.utils.file.streaming import StreamedSourceByteAccounting, stream_analyze_file, stream_source_path
from modelaudit.utils.helpers.cache_decorator import (
    BOUND_CACHE_IDENTITY_CONFIG_KEY,
    CacheIdentityBinding,
    cached_scan,
    should_defer_hash_for_file_backed_onnx,
    should_defer_hash_for_pytorch_read_limit,
)
from modelaudit.utils.helpers.interrupt_handler import check_interrupted
from modelaudit.utils.helpers.types import (
    FilePath,
    ProgressCallback,
)
from modelaudit.utils.lfs import check_lfs_pointer, get_lfs_issue_details, get_lfs_remediation_steps
from modelaudit.utils.repository_context import (
    REPOSITORY_CURRENT_FILE_CONFIG_KEY,
    REPOSITORY_FILE_INVENTORY_CONFIG_KEY,
    REPOSITORY_SCAN_ROOT_CONFIG_KEY,
    RepositoryFileInventory,
    normalize_repository_member_path,
    repository_file_inventory_context_from_config,
)
from modelaudit.utils.sources._huggingface_cache import (
    _find_hf_cache_root,
    _get_hf_cache_root_spellings,
    _get_hf_cache_roots,
    _is_hf_cache_snapshot_alias,
    _path_has_part,
    _resolve_hf_cache_path,
    _trusted_hf_blobs_root,
)
from modelaudit.utils.sources.cloud_storage import (
    is_sensitive_credential_key,
    is_stream_url,
)
from modelaudit.utils.sources.cloud_storage import (
    redact_cloud_error_for_display as _redact_cloud_error_for_display,
)
from modelaudit.utils.sources.cloud_storage import (
    redact_stream_error_for_display as _redact_stream_error_for_display,
)
from modelaudit.utils.sources.cloud_storage import (
    redact_stream_url_for_display as _redact_stream_url_for_display,
)

logger = logging.getLogger("modelaudit.core")
_VALIDATED_SYMLINK_DETECT_FILE_FORMAT = detect_file_format
_VALIDATED_SYMLINK_DETECT_FILE_FORMAT_FROM_MAGIC = detect_file_format_from_magic

_add_asset_to_results = core_results.add_asset_to_results
_add_error_asset_to_results = core_results.add_error_asset_to_results
_DIRECTORY_PRECOUNT_CHILD_LIMIT = 1000
_COMPRESSED_TAR_STREAM_INCOMPLETE_REASON = "tar_compressed_stream_incomplete"
_STREAMING_SOURCE_INTERRUPTED_REASON = "streaming_source_interrupted"


def _repository_member_path_for_scan(scan_path: str, scan_root: Path | None) -> str | None:
    if scan_root is not None:
        try:
            relative_path = Path(scan_path).resolve().relative_to(scan_root).as_posix()
        except (OSError, RuntimeError, ValueError):
            pass
        else:
            normalized_relative = normalize_repository_member_path(relative_path)
            if normalized_relative is not None:
                return normalized_relative
    return normalize_repository_member_path(Path(scan_path).name)


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
_metadata_has_coverage_only_operational_error = core_results.metadata_has_coverage_only_operational_error
_details_match_shard_family_paths = core_results.details_match_shard_family_paths
_metadata_has_incomplete_coverage = core_results.metadata_has_incomplete_coverage
_record_details_have_incomplete_coverage = core_results.record_details_have_incomplete_coverage
_records_have_incomplete_coverage_for_path = core_results.records_have_incomplete_coverage_for_path
_results_have_incomplete_coverage_under_directory = core_results.results_have_incomplete_coverage_under_directory
_results_have_operational_error = core_results.results_have_operational_error
_results_should_be_unsuccessful = core_results.results_should_be_unsuccessful
_scan_result_has_operational_error = core_results.scan_result_has_operational_error
_serialize_streamed_records = core_results.serialize_streamed_records
_to_telemetry_severity = core_results.to_telemetry_severity
_normalize_unclassified_scan_failure = core_results.normalize_unclassified_scan_failure
determine_exit_code = core_results.determine_exit_code
merge_scan_result = core_results.merge_scan_result

HEADER_FORMAT_TO_SCANNER_ID = _registry.get_header_format_to_scanner_ids()
_HF_DOWNLOAD_METADATA_MAX_BYTES = 64 * 1024
_HF_DOWNLOAD_GIT_BOOKKEEPING_MAX_BYTES = 64 * 1024
_HF_HUB_GIT_BOOKKEEPING_MAX_BYTES = 64 * 1024
_HF_CACHE_REF_MAX_BYTES = 4096
_HF_CACHEDIR_TAG_MAX_BYTES = 4096
_HF_CACHEDIR_TAG_CONTENT = (
    "Signature: 8a477f597d28d172789f06886806bc55\n"
    "# This file is a cache directory tag created by huggingface_hub.\n"
    "# For information about cache directory tags, see:\n"
    "#\thttps://bford.info/cachedir/\n"
)


def _record_dvc_output_limit_incomplete(
    results: ModelAuditResultModel,
    scan_metadata: dict[str, Any],
    dvc_path: str,
    resolution: DvcResolution,
) -> None:
    """Fail closed when DVC output expansion was capped."""
    if resolution.omitted_output_count == 0:
        return

    scan_metadata["success"] = False
    _add_issue_to_model(
        results,
        "DVC output limit exceeded - not all declared outputs were scanned",
        severity=IssueSeverity.INFO.value,
        location=dvc_path,
        details={
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "reason": "dvc_output_limit_exceeded",
            "declared_output_count": resolution.declared_output_count,
            "output_limit": resolution.output_limit,
            "resolved_output_count": len(resolution.targets),
            "omitted_output_count": resolution.omitted_output_count,
            "unresolved_omitted_output_count": resolution.unresolved_omitted_output_count,
            "unverified_omitted_output_count": resolution.unverified_omitted_output_count,
            "tail_verification_truncated": resolution.tail_verification_truncated,
        },
        issue_type="dvc_output_limit_exceeded",
    )


def _dvc_omitted_outputs_covered_by_directory_walk(
    dvc_path: str,
    resolution: DvcResolution,
    directory_walk_covered_paths: set[str],
    directory_walk_covered_directories: set[str],
    *,
    skip_file_types: bool,
    metadata_scanner_available: bool,
    scanner_selection_extensions: frozenset[str] | None,
) -> bool:
    """Return whether a directory walk independently covers every bounded omitted DVC target."""

    def directory_files_are_covered(target: Path) -> bool:
        walk_errors: list[OSError] = []
        for root, dirs, files in os.walk(target, followlinks=False, onerror=walk_errors.append):
            for directory_name in dirs:
                directory_path = Path(root) / directory_name
                if directory_path.is_symlink():
                    return False
            for filename in files:
                file_path = os.path.join(root, filename)
                if _is_huggingface_cache_file(file_path):
                    continue
                if (
                    skip_file_types
                    and should_skip_file(
                        file_path,
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_extensions,
                    )
                    and not _preserve_hf_download_sidecar_asset(file_path, scanner_selection_extensions)
                ):
                    continue
                try:
                    file_path_obj = Path(file_path)
                    if file_path_obj.is_symlink() or not file_path_obj.is_file():
                        return False
                    resolved_file = str(file_path_obj.resolve())
                except OSError:
                    return False
                if resolved_file not in directory_walk_covered_paths:
                    return False
        return not walk_errors

    def is_covered(target: Path) -> bool:
        target_str = str(target)
        if target.is_file():
            return target_str in directory_walk_covered_paths
        if not target.is_dir():
            return False
        if target_str not in directory_walk_covered_directories:
            return directory_files_are_covered(target)

        walk_errors: list[OSError] = []
        for root, dirs, files in os.walk(target, followlinks=False, onerror=walk_errors.append):
            if str(Path(root).resolve()) not in directory_walk_covered_directories:
                return False
            for directory_name in dirs:
                try:
                    resolved_directory = str((Path(root) / directory_name).resolve())
                except OSError:
                    return False
                if resolved_directory not in directory_walk_covered_directories:
                    return False
            for filename in files:
                file_path = os.path.join(root, filename)
                if _is_huggingface_cache_file(file_path):
                    continue
                if (
                    skip_file_types
                    and should_skip_file(
                        file_path,
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_extensions,
                    )
                    and not _preserve_hf_download_sidecar_asset(file_path, scanner_selection_extensions)
                ):
                    continue
                try:
                    resolved_file = str(Path(file_path).resolve())
                except OSError:
                    return False
                if resolved_file not in directory_walk_covered_paths:
                    return False
        return not walk_errors

    return dvc_omitted_outputs_covered(
        dvc_path,
        resolution,
        is_covered,
        coverage_budget=len(directory_walk_covered_paths) + len(directory_walk_covered_directories),
    )


_COMPRESSED_HEADER_FORMATS = frozenset({"compressed", "gzip", "bzip2", "xz", "lz4", "zlib"})
_R_SERIALIZED_EXTENSIONS = frozenset({".rds", ".rda", ".rdata"})
_XGBOOST_BINARY_EXTENSIONS = frozenset({".bst"})
_XGBOOST_PICKLE_SPOOF_REASON = "xgboost_binary_pickle_spoof"
_ALTERNATE_VALIDATED_FORMAT_ALLOWED_INCONCLUSIVE_REASONS = {
    "onnx": frozenset({"onnx_weight_distribution_analysis_incomplete"}),
}
_RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON = "recognized_format_scanner_unavailable"
_FORMAT_DETECTION_READ_FAILED_REASON = "format_detection_read_failed"
_XML_MODEL_ROUTING_INCOMPLETE_REASON = "xml_model_routing_incomplete"
_PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON = "protobuf_model_routing_incomplete"
_SENTENCEPIECE_MODEL_PROTO_ROUTING_INCOMPLETE_REASON = "sentencepiece_model_proto_routing_incomplete"
_LLAMAFILE_ROUTING_INCOMPLETE_REASON = "llamafile_routing_incomplete"
_MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON = "mxnet_symbol_routing_incomplete"
_PICKLE_ROUTING_INCOMPLETE_REASON = "pickle_routing_incomplete"
_DVC_SCAN_BUDGET_EXHAUSTED_REASON = "dvc_scan_budget_exhausted"
_DVC_DIRECTORY_WALK_FAILED_REASON = "dvc_directory_walk_failed"
_DVC_DIRECTORY_SYMLINK_UNSCANNED_REASON = "dvc_directory_symlink_unscanned"
_DVC_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON = "dvc_directory_special_file_unscanned"
_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON = "directory_special_file_unscanned"
_MAX_DVC_DIRECTORY_COVERAGE_GAPS = 100
_DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES = 100_000
_DVC_PARENT_FILE_CONFIG_KEY = "_dvc_parent_file"
_DVC_REMAINING_TOTAL_SIZE_CONFIG_KEY = "_dvc_remaining_total_size"
_DVC_TOTAL_SIZE_LIMIT_CONFIG_KEY = "_dvc_total_size_limit"
_DVC_EXCLUDED_PATHS_CONFIG_KEY = "_dvc_excluded_paths"
_DVC_COVERAGE_ROOTS_CONFIG_KEY = "_dvc_coverage_roots"
DVC_EXTERNAL_COVERED_PATHS_CONFIG_KEY = "_dvc_external_covered_paths"
DVC_EXTERNAL_COVERED_DIRECTORIES_CONFIG_KEY = "_dvc_external_covered_directories"
_LOCAL_SOURCE_RECEIPT_CONFIG_KEY = "_local_source_receipt"
_LOCAL_SOURCE_BOUND_GUARD_CONFIG_KEY = "_local_source_bound_guard"
_BOUND_CACHE_IDENTITY_CONFIG_KEY = BOUND_CACHE_IDENTITY_CONFIG_KEY
_INCOMPLETE_SHARD_CHECK_NAMES = frozenset(
    {
        "Shard Scan",
        "Sharded Model Coverage Check",
        "Sharded Model Membership Check",
    }
)


def _path_matches_shard_family(candidate_path: str | None, shard_paths: set[str]) -> bool:
    if not isinstance(candidate_path, str):
        return False
    try:
        resolved_candidate = Path(candidate_path).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    resolved_candidate_str = str(resolved_candidate)
    if resolved_candidate_str in shard_paths:
        return True
    if not resolved_candidate.is_dir():
        return False
    return any(Path(shard_path).is_relative_to(resolved_candidate) for shard_path in shard_paths)


def _shard_family_has_incomplete_coverage(
    records: Iterable[Any],
    shard_paths: set[str],
    *,
    only_detected_shard_family: bool = True,
    allow_skipped_check_exemption: bool = False,
) -> bool:
    for record in records:
        if not _record_details_have_incomplete_coverage(
            record,
            allow_skipped_check_exemption=allow_skipped_check_exemption,
        ):
            continue
        if _path_matches_shard_family(getattr(record, "location", None), shard_paths):
            return True
        details = getattr(record, "details", None)
        if _details_match_shard_family_paths(
            details, lambda candidate: _path_matches_shard_family(candidate, shard_paths)
        ):
            return True
        if only_detected_shard_family and getattr(record, "name", None) in _INCOMPLETE_SHARD_CHECK_NAMES:
            return True
    return False


_OPENVINO_SCANNED_XML_COMPANIONS_CONFIG_KEY = "_openvino_scanned_xml_companions"


def _record_incomplete_dvc_resolution(
    results: ModelAuditResultModel,
    scan_metadata: dict[str, Any],
    dvc_file: str,
    resolution: DvcResolution,
) -> None:
    """Record unresolved DVC outputs as operationally incomplete coverage."""
    if not resolution.analysis_incomplete:
        return

    scan_metadata["success"] = False
    scan_metadata["has_operational_errors"] = True
    details: dict[str, Any] = {
        "analysis_incomplete": True,
        "scan_outcome_reason": DVC_ANALYSIS_INCOMPLETE_REASON,
        "dvc_file": dvc_file,
        "resolved_outputs": list(resolution.resolved_paths),
    }
    if resolution.unresolved_outputs:
        details["unresolved_outputs"] = list(resolution.unresolved_outputs)
    if resolution.incomplete_reason:
        details["incomplete_reason"] = resolution.incomplete_reason

    _add_issue_to_model(
        results,
        "DVC output resolution incomplete - declared outputs could not be fully scanned",
        severity=IssueSeverity.INFO.value,
        location=dvc_file,
        details=details,
    )


def _record_incomplete_dvc_scan_budget(
    results: ModelAuditResultModel,
    scan_metadata: dict[str, Any],
    dvc_file: str,
    *,
    budget_type: str,
    limit: int,
) -> None:
    """Record exhaustion of a shared DVC scan budget."""
    scan_metadata["success"] = False
    scan_metadata["has_operational_errors"] = True
    _add_issue_to_model(
        results,
        f"DVC scan {budget_type} budget exhausted before all resolved outputs were scanned",
        severity=IssueSeverity.INFO.value,
        location=dvc_file,
        details={
            "analysis_incomplete": True,
            "operational_error": True,
            "scan_outcome_reason": _DVC_SCAN_BUDGET_EXHAUSTED_REASON,
            "budget_type": budget_type,
            "limit": limit,
        },
    )


def _record_directory_special_file_unscanned(
    results: ModelAuditResultModel,
    scan_metadata: dict[str, Any],
    file_path: str,
) -> None:
    """Fail closed when a directory entry is not a regular file."""
    scan_metadata["success"] = False
    scan_metadata["has_operational_errors"] = True
    _add_issue_to_model(
        results,
        "Special directory entry could not be scanned",
        severity=IssueSeverity.INFO.value,
        location=file_path,
        details={
            "analysis_incomplete": True,
            "operational_error": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": _DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON,
        },
        issue_type=_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON,
    )


_XGBOOST_UBJSON_ROUTING_INCOMPLETE_REASON = "xgboost_ubjson_routing_incomplete"
_ONNX_ROUTING_INCOMPLETE_REASON = "onnx_routing_incomplete"
_TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON = "tensorflow_protobuf_routing_incomplete"
_ShardFamilyKey = tuple[str, str, int | None]
_ScanEntry = tuple[str, list[str], _ShardFamilyKey | None, str | None]
_FileTargetIdentityKey = tuple[Any, ...]
_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY = "shard_family_cache_fingerprint"
_TRUSTED_STREAM_SHARD_PARENT_PREFIXES = (
    "modelaudit_hf_",
    "modelaudit_pth_stream_",
    "modelaudit_stream_",
)
_TRUSTED_STREAM_SHARD_ROOT_TOKEN = object()


@dataclass(frozen=True)
class _TrustedStreamShardRoot:
    """Internal marker for a source-owned persistent streaming root."""

    path: Path
    token: object


@dataclass(frozen=True)
class _DirectoryOwnerSnapshotEntry:
    """No-follow identity for one lexical directory-owner namespace entry."""

    relative_parts: tuple[str, ...]
    entry_type: str
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    link_count: int
    raw_link_target: str | None


class _DirectoryOwnerSnapshotLimitError(RuntimeError):
    """Raised when a logical-owner namespace exceeds its bounded inventory."""


class _LocalSourceBoundaryError(RuntimeError):
    """Raised when a local source no longer matches its dispatch receipt."""


def _directory_owner_stat_mode(entry_stat: os.stat_result) -> int:
    return int(getattr(entry_stat, "st_mode", 0) or 0)


def _directory_owner_snapshot_entry(
    entry_path: Path,
    relative_parts: tuple[str, ...],
    *,
    entry_stat: os.stat_result | None = None,
    raw_link_target: str | None = None,
) -> _DirectoryOwnerSnapshotEntry:
    """Capture a lexical entry without following a symlink or reparse point."""
    if entry_stat is None:
        entry_stat = entry_path.lstat()
    entry_mode = _directory_owner_stat_mode(entry_stat)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(entry_stat, "st_file_attributes", 0) or 0
    is_link = stat.S_ISLNK(entry_mode) or bool(reparse_flag and file_attributes & reparse_flag)
    if is_link:
        entry_type = "link"
    elif stat.S_ISREG(entry_mode):
        entry_type = "file"
    elif stat.S_ISDIR(entry_mode):
        entry_type = "directory"
    elif stat.S_ISFIFO(entry_mode):
        entry_type = "fifo"
    elif stat.S_ISSOCK(entry_mode):
        entry_type = "socket"
    elif stat.S_ISCHR(entry_mode):
        entry_type = "character_device"
    elif stat.S_ISBLK(entry_mode):
        entry_type = "block_device"
    else:
        entry_type = "other"

    if is_link and raw_link_target is None:
        with suppress(OSError):
            raw_link_target = os.readlink(entry_path)

    return _DirectoryOwnerSnapshotEntry(
        relative_parts=relative_parts,
        entry_type=entry_type,
        device=entry_stat.st_dev,
        inode=entry_stat.st_ino,
        mode=entry_mode,
        size=entry_stat.st_size,
        mtime_ns=entry_stat.st_mtime_ns,
        ctime_ns=entry_stat.st_ctime_ns,
        link_count=entry_stat.st_nlink,
        raw_link_target=raw_link_target,
    )


def _retained_descriptor_paths(descriptor: int) -> tuple[Path, ...]:
    """Return descriptor aliases that remain usable by child scanner processes."""
    return (
        Path("/proc") / str(os.getpid()) / "fd" / str(descriptor),
        Path("/proc/self/fd") / str(descriptor),
        Path("/dev/fd") / str(descriptor),
    )


@contextmanager
def _bound_directory_owner_scan_path(
    root_path: Path,
    *,
    trusted_root_symlink: bool = False,
) -> Iterator[str]:
    """Yield a descriptor-backed owner root when the platform exposes one."""
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    expected_root_stat = os.stat(root_path) if trusted_root_symlink else root_path.lstat()
    root_flags = directory_flags & ~getattr(os, "O_NOFOLLOW", 0) if trusted_root_symlink else directory_flags
    root_descriptor = os.open(root_path, root_flags)
    try:
        root_stat = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(_directory_owner_stat_mode(expected_root_stat))
            or not stat.S_ISDIR(_directory_owner_stat_mode(root_stat))
            or not _directory_owner_snapshot_stat_matches(root_stat, expected_root_stat)
        ):
            raise OSError("Directory owner root changed before owner dispatch")

        for descriptor_root in _retained_descriptor_paths(root_descriptor):
            with suppress(OSError):
                descriptor_stat = descriptor_root.stat()
                if stat.S_ISDIR(_directory_owner_stat_mode(descriptor_stat)) and _directory_owner_snapshot_stat_matches(
                    descriptor_stat,
                    root_stat,
                ):
                    yield str(descriptor_root)
                    return

        raise OSError("Descriptor-backed directory owner path is unavailable")
    finally:
        os.close(root_descriptor)


def _directory_owner_snapshot_stat_matches(
    current: os.stat_result,
    expected: os.stat_result,
) -> bool:
    """Return whether one lexical entry kept the same no-follow identity."""
    identity_fields: tuple[str, ...] = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if not (stat.S_ISDIR(_directory_owner_stat_mode(current)) and stat.S_ISDIR(_directory_owner_stat_mode(expected))):
        identity_fields = (*identity_fields, "st_nlink")
    return all(getattr(current, field) == getattr(expected, field) for field in identity_fields)


def _capture_directory_owner_namespace_by_descriptor(
    root_path: Path,
    owner_class: type[BaseScanner] | None,
    *,
    deadline: float,
    max_entries: int,
    trusted_root_symlink: bool = False,
) -> tuple[_DirectoryOwnerSnapshotEntry, ...]:
    """Capture a namespace through no-follow directory descriptors."""
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    expected_root_stat = os.stat(root_path) if trusted_root_symlink else root_path.lstat()
    root_flags = directory_flags & ~getattr(os, "O_NOFOLLOW", 0) if trusted_root_symlink else directory_flags
    root_descriptor = os.open(root_path, root_flags)
    root_stat = os.fstat(root_descriptor)
    if (
        not stat.S_ISDIR(_directory_owner_stat_mode(expected_root_stat))
        or not stat.S_ISDIR(_directory_owner_stat_mode(root_stat))
        or not _directory_owner_snapshot_stat_matches(root_stat, expected_root_stat)
    ):
        os.close(root_descriptor)
        raise OSError("Directory owner root changed before namespace snapshot")

    snapshot = [
        _directory_owner_snapshot_entry(
            root_path,
            (),
            entry_stat=root_stat,
        )
    ]
    entries_seen = 0
    frames: list[tuple[int, Any, os.stat_result, tuple[str, ...]]] = []
    try:
        frames.append((root_descriptor, os.scandir(root_descriptor), root_stat, ()))
        root_descriptor = -1
        while frames:
            if time.time() > deadline:
                raise TimeoutError("Directory owner namespace snapshot timed out")

            directory_descriptor, entries, expected_directory_stat, parent_parts = frames[-1]
            try:
                lexical_entry = next(entries)
            except StopIteration:
                final_directory_stat = os.fstat(directory_descriptor)
                if not _directory_owner_snapshot_stat_matches(final_directory_stat, expected_directory_stat):
                    raise OSError("Directory changed during owner namespace snapshot") from None
                entries.close()
                os.close(directory_descriptor)
                frames.pop()
                continue

            entries_seen += 1
            if entries_seen > max_entries:
                raise _DirectoryOwnerSnapshotLimitError(
                    f"Directory owner namespace exceeds {max_entries} entries",
                )

            relative_parts = (*parent_parts, lexical_entry.name)
            entry_stat = os.stat(
                lexical_entry.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            file_attributes = getattr(entry_stat, "st_file_attributes", 0) or 0
            entry_mode = _directory_owner_stat_mode(entry_stat)
            is_link = stat.S_ISLNK(entry_mode) or bool(reparse_flag and file_attributes & reparse_flag)
            raw_link_target: str | None = None
            if is_link and os.readlink in os.supports_dir_fd:
                with suppress(OSError):
                    raw_link_target = os.readlink(lexical_entry.name, dir_fd=directory_descriptor)

            entry_path = root_path.joinpath(*relative_parts)
            directory_in_scope = stat.S_ISDIR(entry_mode) and (
                owner_class is None or owner_class.directory_owner_directory_in_scope(relative_parts)
            )
            should_descend = stat.S_ISDIR(entry_mode) and (
                owner_class is None or owner_class.directory_owner_should_descend_into_directory(relative_parts)
            )
            if directory_in_scope or owner_class is None or owner_class.directory_owner_source_in_scope(relative_parts):
                snapshot.append(
                    _directory_owner_snapshot_entry(
                        entry_path,
                        relative_parts,
                        entry_stat=entry_stat,
                        raw_link_target=raw_link_target,
                    )
                )

            if not should_descend or is_link:
                continue

            child_descriptor = os.open(
                lexical_entry.name,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            child_stat = os.fstat(child_descriptor)
            if not _directory_owner_snapshot_stat_matches(child_stat, entry_stat):
                os.close(child_descriptor)
                raise OSError("Directory changed before owner namespace descent")
            try:
                child_entries = os.scandir(child_descriptor)
            except Exception:
                os.close(child_descriptor)
                raise
            frames.append((child_descriptor, child_entries, child_stat, relative_parts))
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        while frames:
            directory_descriptor, entries, _expected_directory_stat, _parent_parts = frames.pop()
            entries.close()
            os.close(directory_descriptor)

    return tuple(sorted(snapshot, key=lambda entry: entry.relative_parts))


def _capture_directory_owner_namespace(
    root_path: Path,
    owner_class: type[BaseScanner] | None,
    *,
    deadline: float,
    max_entries: int,
    trusted_root_symlink: bool = False,
) -> tuple[_DirectoryOwnerSnapshotEntry, ...]:
    """Capture every lexical entry the logical directory owner may inspect."""
    if os.scandir in os.supports_fd and os.open in os.supports_dir_fd:
        return _capture_directory_owner_namespace_by_descriptor(
            root_path,
            owner_class,
            deadline=deadline,
            max_entries=max_entries,
            trusted_root_symlink=trusted_root_symlink,
        )

    root_stat = os.stat(root_path) if trusted_root_symlink else root_path.lstat()
    if not stat.S_ISDIR(_directory_owner_stat_mode(root_stat)):
        raise OSError("Directory owner root is not a regular directory")
    snapshot = [_directory_owner_snapshot_entry(root_path, (), entry_stat=root_stat)]
    entries_seen = 0
    pending_directories: list[tuple[Path, tuple[str, ...], os.stat_result]] = [(root_path, (), root_stat)]
    while pending_directories:
        root, root_relative_parts, expected_root_stat = pending_directories.pop()
        current_root_stat = os.stat(root) if trusted_root_symlink and not root_relative_parts else root.lstat()
        if not _directory_owner_snapshot_stat_matches(current_root_stat, expected_root_stat):
            raise OSError("Directory changed before owner namespace descent")
        child_directories: list[tuple[Path, tuple[str, ...], os.stat_result]] = []
        with os.scandir(root) as entries:
            for lexical_entry in entries:
                if time.time() > deadline:
                    raise TimeoutError("Directory owner namespace snapshot timed out")
                entries_seen += 1
                if entries_seen > max_entries:
                    raise _DirectoryOwnerSnapshotLimitError(
                        f"Directory owner namespace exceeds {max_entries} entries",
                    )

                relative_parts = (*root_relative_parts, lexical_entry.name)
                entry_path = root_path.joinpath(*relative_parts)
                entry_stat = entry_path.lstat()
                reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                file_attributes = getattr(entry_stat, "st_file_attributes", 0) or 0
                entry_mode = _directory_owner_stat_mode(entry_stat)
                is_link = stat.S_ISLNK(entry_mode) or bool(reparse_flag and file_attributes & reparse_flag)
                directory_in_scope = stat.S_ISDIR(entry_mode) and (
                    owner_class is None or owner_class.directory_owner_directory_in_scope(relative_parts)
                )
                should_descend = stat.S_ISDIR(entry_mode) and (
                    owner_class is None or owner_class.directory_owner_should_descend_into_directory(relative_parts)
                )
                if should_descend and not is_link:
                    child_directories.append((entry_path, relative_parts, entry_stat))

                if not (
                    directory_in_scope
                    or owner_class is None
                    or owner_class.directory_owner_source_in_scope(relative_parts)
                ):
                    continue
                snapshot.append(
                    _directory_owner_snapshot_entry(
                        entry_path,
                        relative_parts,
                        entry_stat=entry_stat,
                    )
                )
        current_root_stat = os.stat(root) if trusted_root_symlink and not root_relative_parts else root.lstat()
        if not _directory_owner_snapshot_stat_matches(current_root_stat, expected_root_stat):
            raise OSError("Directory changed during owner namespace snapshot")
        pending_directories.extend(sorted(child_directories, reverse=True))
    return tuple(sorted(snapshot, key=lambda entry: entry.relative_parts))


def _directory_owner_snapshot_changed_paths(
    before: tuple[_DirectoryOwnerSnapshotEntry, ...],
    after: tuple[_DirectoryOwnerSnapshotEntry, ...],
) -> set[tuple[str, ...]]:
    """Return added, removed, renamed, retyped, or identity-changed paths."""
    before_by_path = {entry.relative_parts: entry for entry in before}
    after_by_path = {entry.relative_parts: entry for entry in after}
    return {
        relative_parts
        for relative_parts in before_by_path.keys() | after_by_path.keys()
        if not _directory_owner_snapshot_entries_match(
            before_by_path.get(relative_parts),
            after_by_path.get(relative_parts),
        )
    }


def _directory_owner_snapshot_entries_match(
    before: _DirectoryOwnerSnapshotEntry | None,
    after: _DirectoryOwnerSnapshotEntry | None,
) -> bool:
    if before is None or after is None:
        return before is after
    if before.entry_type == after.entry_type == "directory":
        return all(
            getattr(before, field) == getattr(after, field)
            for field in (
                "relative_parts",
                "entry_type",
                "device",
                "inode",
                "mode",
                "size",
                "mtime_ns",
                "ctime_ns",
                "raw_link_target",
            )
        )
    return before == after


def _terminal_local_namespace_changed(
    initial: tuple[_DirectoryOwnerSnapshotEntry, ...],
    terminal: tuple[_DirectoryOwnerSnapshotEntry, ...],
    *,
    deleted_relative_parts: set[tuple[str, ...]],
) -> bool:
    """Compare a retained namespace while allowing only scanner-owned deletions."""
    if not deleted_relative_parts:
        return bool(_directory_owner_snapshot_changed_paths(initial, terminal))

    initial_entries = {entry.relative_parts: entry for entry in initial}
    terminal_entries = {entry.relative_parts: entry for entry in terminal}
    if set(terminal_entries) != set(initial_entries) - deleted_relative_parts:
        return True
    stable_directory_fields = ("relative_parts", "entry_type", "device", "inode", "mode", "raw_link_target")
    for relative_parts, terminal_entry in terminal_entries.items():
        initial_entry = initial_entries[relative_parts]
        if initial_entry.entry_type == terminal_entry.entry_type == "directory":
            if any(
                getattr(initial_entry, field) != getattr(terminal_entry, field) for field in stable_directory_fields
            ):
                return True
            continue
        if not _directory_owner_snapshot_entries_match(initial_entry, terminal_entry):
            return True
    return False


@dataclass(frozen=True)
class _FileIdentitySnapshot:
    """Stable identity fields for a path-sensitive companion file."""

    lstat: tuple[int, int, int, int, int, int]
    stat: tuple[int, int, int, int, int, int] | None
    resolved_path: str | None


def _make_trusted_stream_shard_root(path: FilePath) -> object:
    """Mark a persistent root selected by a trusted remote-source dispatcher."""
    return _TrustedStreamShardRoot(
        path=Path(path).expanduser().absolute(),
        token=_TRUSTED_STREAM_SHARD_ROOT_TOKEN,
    )


def _redacted_stream_url_for_reporting(stream_url: str) -> str:
    """Return a stream source identifier safe for persisted scan output."""
    return _redact_stream_url_for_display(stream_url)


def _redacted_scan_path_for_reporting(path: str) -> str:
    if is_stream_url(path):
        return f"stream://{_redacted_stream_url_for_reporting(path[9:])}"
    return path


def _redacted_scan_error_for_reporting(error: object, path: str) -> str:
    if is_stream_url(path):
        return _redact_stream_error_for_display(error, path[9:])
    return str(error)


def _redact_stream_value_for_reporting(value: Any, stream_url: str, report_url: str) -> Any:
    if isinstance(value, BaseModel):
        return _redact_stream_value_for_reporting(value.model_dump(mode="python"), stream_url, report_url)
    if isinstance(value, AnyUrl):
        return _redact_stream_value_for_reporting(str(value), stream_url, report_url)
    if isinstance(value, os.PathLike):
        return _redact_stream_value_for_reporting(os.fspath(value), stream_url, report_url)
    if isinstance(value, str):
        return _redact_cloud_error_for_display(value.replace(stream_url, report_url))
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return b"<binary data>"
        return _redact_stream_value_for_reporting(decoded, stream_url, report_url).encode("utf-8")
    if isinstance(value, bytearray):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return bytearray(b"<binary data>")
        return bytearray(_redact_stream_value_for_reporting(decoded, stream_url, report_url), "utf-8")
    if isinstance(value, dict):
        redacted_mapping: dict[Any, Any] = {}
        for key, item in value.items():
            redacted_key = _redact_stream_value_for_reporting(key, stream_url, report_url)
            redacted_mapping[redacted_key] = (
                "<redacted>"
                if is_sensitive_credential_key(key)
                else _redact_stream_value_for_reporting(item, stream_url, report_url)
            )
        return redacted_mapping
    if isinstance(value, list):
        return [_redact_stream_value_for_reporting(item, stream_url, report_url) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_stream_value_for_reporting(item, stream_url, report_url) for item in value)
    if isinstance(value, set):
        return {_redact_stream_value_for_reporting(item, stream_url, report_url) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_redact_stream_value_for_reporting(item, stream_url, report_url) for item in value)
    return value


def _redact_stream_record_for_reporting(record: Issue | Check, stream_url: str, report_url: str) -> None:
    for attr in ("location", "message", "why", "rule_code", "type", "name"):
        value = getattr(record, attr, None)
        if isinstance(value, str):
            setattr(record, attr, _redact_stream_value_for_reporting(value, stream_url, report_url))
    if record.details:
        record.details = _redact_stream_value_for_reporting(record.details, stream_url, report_url)
    if record.model_extra:
        redacted_extra = _redact_stream_value_for_reporting(record.model_extra, stream_url, report_url)
        record.model_extra.clear()
        record.model_extra.update(redacted_extra)


def _redact_stream_scan_result_for_reporting(scan_result: ScanResult, stream_url: str, report_url: str) -> None:
    """Strip signed query material from scanner-owned records before aggregation."""
    for issue in scan_result.issues:
        _redact_stream_record_for_reporting(issue, stream_url, report_url)
    for check in scan_result.checks:
        _redact_stream_record_for_reporting(check, stream_url, report_url)

    if scan_result.metadata:
        scan_result.metadata = _redact_stream_value_for_reporting(scan_result.metadata, stream_url, report_url)
        scan_result._refresh_metadata_dependent_state()


def _rebase_bound_directory_owner_value_for_reporting(value: Any, report_root: Path) -> Any:
    """Rewrite descriptor-cwd relative paths back to the requested report root."""
    if isinstance(value, str):
        if value == os.curdir:
            return str(report_root)
        if os.path.isabs(value) or "://" in value or value.startswith("../"):
            return value
        relative_candidate = report_root / value
        if relative_candidate.exists():
            return str(relative_candidate)
        return value
    if isinstance(value, dict):
        return {
            _rebase_bound_directory_owner_value_for_reporting(key, report_root): (
                _rebase_bound_directory_owner_value_for_reporting(item, report_root)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_rebase_bound_directory_owner_value_for_reporting(item, report_root) for item in value]
    if isinstance(value, tuple):
        return tuple(_rebase_bound_directory_owner_value_for_reporting(item, report_root) for item in value)
    if isinstance(value, set):
        return {_rebase_bound_directory_owner_value_for_reporting(item, report_root) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_rebase_bound_directory_owner_value_for_reporting(item, report_root) for item in value)
    return value


def _normalize_directory_owner_scan_result_for_reporting(
    scan_result: ScanResult,
    owner_scan_path: str,
    report_path: str,
) -> None:
    """Rewrite descriptor-only owner scan paths before aggregate reporting."""
    if owner_scan_path != os.curdir:
        _redact_stream_scan_result_for_reporting(scan_result, owner_scan_path, report_path)
        return

    report_root = Path(report_path)
    for issue in scan_result.issues:
        for attr in ("location", "message", "why", "rule_code", "type", "name"):
            value = getattr(issue, attr, None)
            if isinstance(value, str):
                setattr(issue, attr, _rebase_bound_directory_owner_value_for_reporting(value, report_root))
        if issue.details:
            issue.details = _rebase_bound_directory_owner_value_for_reporting(issue.details, report_root)
        if issue.model_extra:
            rebased_extra = _rebase_bound_directory_owner_value_for_reporting(issue.model_extra, report_root)
            issue.model_extra.clear()
            issue.model_extra.update(rebased_extra)
    for check in scan_result.checks:
        for attr in ("location", "message", "why", "rule_code", "type", "name"):
            value = getattr(check, attr, None)
            if isinstance(value, str):
                setattr(check, attr, _rebase_bound_directory_owner_value_for_reporting(value, report_root))
        if check.details:
            check.details = _rebase_bound_directory_owner_value_for_reporting(check.details, report_root)
        if check.model_extra:
            rebased_extra = _rebase_bound_directory_owner_value_for_reporting(check.model_extra, report_root)
            check.model_extra.clear()
            check.model_extra.update(rebased_extra)
    if scan_result.metadata:
        scan_result.metadata = _rebase_bound_directory_owner_value_for_reporting(scan_result.metadata, report_root)
        scan_result._refresh_metadata_dependent_state()


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


def _trusted_stream_shard_family_group(
    source: Path,
    resolved_source: Path,
    family_group: str,
    trusted_root_marker: object | None = None,
) -> str | None:
    """Scope a trusted stream group to the artifact's logical staging parent."""

    def trusted_root_is_private(path: Path) -> bool:
        try:
            root_stat = os.stat(path, follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISDIR(root_stat.st_mode):
            return False
        if os.name != "nt":
            get_effective_uid = getattr(os, "geteuid", None)
            if callable(get_effective_uid) and root_stat.st_uid != get_effective_uid():
                return False
            if stat.S_IMODE(root_stat.st_mode) & 0o022:
                return False
        return True

    try:
        logical_parent = source.absolute().parent.resolve(strict=True)
        trusted_root: Path | None = None
        if (
            isinstance(trusted_root_marker, _TrustedStreamShardRoot)
            and trusted_root_marker.token is _TRUSTED_STREAM_SHARD_ROOT_TOKEN
        ):
            candidate_root = trusted_root_marker.path.resolve(strict=True)
            if trusted_root_is_private(candidate_root):
                trusted_root = candidate_root

        if trusted_root is None:
            temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
            candidate = logical_parent
            while candidate != temp_root and candidate != candidate.parent:
                if (
                    candidate.parent == temp_root
                    and candidate.name.startswith(_TRUSTED_STREAM_SHARD_PARENT_PREFIXES)
                    and trusted_root_is_private(candidate)
                ):
                    trusted_root = candidate
                    break
                candidate = candidate.parent
        if trusted_root is None:
            return None
        if not is_within_directory(str(trusted_root), str(logical_parent)) or not is_within_directory(
            str(trusted_root), str(resolved_source)
        ):
            return None
        relative_parent = logical_parent.relative_to(trusted_root)
    except (OSError, RuntimeError, ValueError):
        return None

    scope = hashlib.sha256()
    scope.update(family_group.encode("utf-8", errors="surrogatepass"))
    scope.update(b"\0")
    scope.update(os.path.normcase(relative_parent.as_posix()).encode("utf-8", errors="surrogatepass"))
    return f"stream-staging:{scope.hexdigest()}"


def _snapshot_validated_shard_target(
    source_path: str,
    *,
    resolved_path: str | None = None,
    family_group: str | None = None,
    family_group_policy: str | None = None,
    trusted_root_marker: object | None = None,
    authoritative_shard_index_base: str | None = None,
    authoritative_shard_index_path: str | None = None,
    authoritative_shard_index_fingerprint: str | None = None,
    authoritative_shard_index_generation: int | None = None,
) -> ValidatedShardTargets:
    """Snapshot one selected shard path after resolving it to a regular file."""
    source = Path(source_path)
    shard_match = ShardedModelDetector.match_shard_filename(source.name)
    if shard_match is None or not isinstance(shard_match.get("expected_total_shards"), int):
        return {}

    try:
        resolved_source = source.resolve(strict=True)
        resolved_target = Path(resolved_path).resolve(strict=True) if resolved_path is not None else resolved_source
        if os.path.normcase(os.path.normpath(str(resolved_source))) != os.path.normcase(
            os.path.normpath(str(resolved_target))
        ):
            return {}
        target_stat = os.stat(resolved_target, follow_symlinks=False)
    except (OSError, RuntimeError):
        return {}
    if not stat.S_ISREG(target_stat.st_mode):
        return {}

    target: dict[str, int | str] = {
        "resolved_path": str(resolved_target),
        "device": target_stat.st_dev,
        "inode": target_stat.st_ino,
        "size": target_stat.st_size,
        "mtime_ns": target_stat.st_mtime_ns,
        "ctime_ns": target_stat.st_ctime_ns,
        "nlink": target_stat.st_nlink,
    }
    if family_group_policy == "explicit" and family_group:
        target["family_group"] = family_group
    elif family_group_policy == "stream_staging":
        trusted_family_group = (
            _trusted_stream_shard_family_group(
                source,
                resolved_source,
                family_group,
                trusted_root_marker,
            )
            if family_group
            else None
        )
        if trusted_family_group:
            target["family_group"] = trusted_family_group
    if (
        authoritative_shard_index_base in {"zero", "one"}
        and isinstance(authoritative_shard_index_path, str)
        and authoritative_shard_index_path
        and isinstance(authoritative_shard_index_fingerprint, str)
        and authoritative_shard_index_fingerprint
        and isinstance(authoritative_shard_index_generation, int)
        and not isinstance(authoritative_shard_index_generation, bool)
        and authoritative_shard_index_generation > 0
    ):
        target["authoritative_shard_index_base"] = authoritative_shard_index_base
        target["authoritative_shard_index_path"] = os.path.normcase(
            os.path.normpath(os.path.abspath(authoritative_shard_index_path))
        )
        target["authoritative_shard_index_fingerprint"] = authoritative_shard_index_fingerprint
        target["authoritative_shard_index_generation"] = authoritative_shard_index_generation
    return {str(source.absolute()): target}


def _snapshot_local_source_receipt(source_path: str | os.PathLike[str]) -> dict[str, int | str] | None:
    """Capture the filesystem object selected by a local source path."""
    for _attempt in range(3):
        try:
            lexical_entries = _local_source_lexical_identity_entries(source_path)
            resolved_source = Path(source_path).resolve(strict=True)
            source_stat = os.stat(resolved_source, follow_symlinks=False)
            verified_lexical_entries = _local_source_lexical_identity_entries(source_path)
            verified_resolved_source = Path(source_path).resolve(strict=True)
            verified_source_stat = os.stat(verified_resolved_source, follow_symlinks=False)
        except (OSError, RuntimeError, ValueError):
            continue

        lexical_identity = _local_source_lexical_identity(lexical_entries)
        if lexical_identity != _local_source_lexical_identity(verified_lexical_entries):
            continue
        if os.path.normcase(os.path.normpath(str(resolved_source))) != os.path.normcase(
            os.path.normpath(str(verified_resolved_source))
        ):
            continue
        receipt = _local_source_receipt_from_stat(str(resolved_source), lexical_identity, source_stat)
        if _local_source_stat_matches_receipt(verified_source_stat, receipt):
            return receipt
    return None


def _snapshot_regular_file_target(path: str | os.PathLike[str]) -> dict[str, int | str] | None:
    """Capture a regular file identity for later descriptor-bound dispatch."""
    try:
        # Callers already supply a trusted, resolved target. Resolving it again
        # would re-enter an untrusted alias path and reopen a pathname race.
        resolved_path = Path(os.path.abspath(os.fspath(path)))
        target_stat = os.stat(resolved_path, follow_symlinks=False)
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(target_stat.st_mode):
        return None
    return {
        "resolved_path": str(resolved_path),
        "device": target_stat.st_dev,
        "inode": target_stat.st_ino,
        "size": target_stat.st_size,
        "mtime_ns": target_stat.st_mtime_ns,
        "ctime_ns": target_stat.st_ctime_ns,
        "nlink": target_stat.st_nlink,
    }


def _local_source_lexical_identity(entries: list[tuple[Path, os.stat_result]]) -> str:
    """Hash the lexical path entries observed around local source resolution."""
    return hashlib.sha256(
        repr(
            [
                (
                    os.path.normcase(os.path.normpath(str(entry_path))),
                    entry_stat.st_dev,
                    entry_stat.st_ino,
                    stat.S_IFMT(entry_stat.st_mode),
                    entry_stat.st_size,
                    entry_stat.st_mtime_ns,
                    entry_stat.st_ctime_ns,
                    entry_stat.st_nlink,
                    getattr(entry_stat, "st_file_attributes", 0) or 0,
                )
                for entry_path, entry_stat in entries
            ]
        ).encode("utf-8", errors="surrogateescape")
    ).hexdigest()


def _local_source_lexical_identity_entries(
    source_path: str | os.PathLike[str],
) -> list[tuple[Path, os.stat_result]]:
    """Return the final lexical entry and any reparse components leading to it."""
    absolute_source = Path(os.path.abspath(os.fspath(source_path)))
    parts = absolute_source.parts
    if not parts:
        raise ValueError("local source path has no components")

    current = Path(parts[0])
    candidates = [current] if len(parts) == 1 else []
    for part in parts[1:]:
        current /= part
        candidates.append(current)

    entries: list[tuple[Path, os.stat_result]] = []
    for candidate in candidates:
        entry_stat = os.lstat(candidate)
        is_final = candidate == absolute_source
        is_reparse_point = _stat_is_windows_reparse_point(entry_stat)
        if is_final or stat.S_ISLNK(entry_stat.st_mode) or is_reparse_point or os.name == "nt":
            entries.append((candidate, entry_stat))
    return entries


def _local_source_stat_matches_receipt(
    current: os.stat_result,
    expected: dict[str, int | str],
) -> bool:
    """Return whether an opened directory is the target captured at dispatch."""
    expected_fields = {
        "device": current.st_dev,
        "inode": current.st_ino,
        "mode_type": stat.S_IFMT(current.st_mode),
        "size": current.st_size,
        "mtime_ns": current.st_mtime_ns,
        "ctime_ns": current.st_ctime_ns,
        "nlink": current.st_nlink,
    }
    return all(expected.get(field) == value for field, value in expected_fields.items())


def _local_source_lexical_entry_matches_receipt(
    current: os.stat_result,
    expected: dict[str, int | str],
) -> bool:
    """Compare a lexical entry without treating directory contents as identity."""
    if stat.S_IFMT(current.st_mode) == stat.S_IFDIR and expected.get("mode_type") == stat.S_IFDIR:
        return current.st_dev == expected.get("device") and current.st_ino == expected.get("inode")
    return _local_source_stat_matches_receipt(current, expected)


@dataclass
class _BoundLocalSourceGuard:
    """Retained POSIX path chain that binds one local source selection."""

    bound_path: str
    receipt: dict[str, int | str]
    guarded_descriptors: tuple[tuple[int, dict[str, int | str]], ...]
    guarded_entries: tuple[tuple[int, str, int, dict[str, int | str]], ...]
    staging_path: Path | None = None
    staging_stat: os.stat_result | None = None
    staging_parent_fd: int | None = None
    staging_fd: int | None = None
    staged_name: str | None = None
    staged_entry_stat: os.stat_result | None = None
    staging_mutation_monitor: _StagingMutationMonitor | None = None
    staging_changed: bool = False
    closed: bool = False

    def changed(self, *, allow_directory_content_changes: bool = False) -> bool:
        """Return whether any retained path component changed after acquisition."""
        if self.closed:
            return True
        for descriptor, expected in self.guarded_descriptors:
            try:
                current = os.fstat(descriptor)
            except OSError:
                return True
            if (
                current.st_dev != expected.get("device")
                or current.st_ino != expected.get("inode")
                or stat.S_IFMT(current.st_mode) != expected.get("mode_type")
            ):
                return True
        for parent_descriptor, name, child_descriptor, lexical_receipt in self.guarded_entries:
            try:
                current_lexical_entry = os.stat(
                    name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                current_entry = os.stat(name, dir_fd=parent_descriptor)
                opened_child = os.fstat(child_descriptor)
            except OSError:
                return True
            if not _local_source_lexical_entry_matches_receipt(
                current_lexical_entry,
                lexical_receipt,
            ) or not os.path.samestat(current_entry, opened_child):
                return True
        try:
            final_source = os.fstat(self.guarded_descriptors[-1][0])
        except (IndexError, OSError):
            return True
        final_source_matches = (
            _local_source_lexical_entry_matches_receipt(final_source, self.receipt)
            if allow_directory_content_changes
            else _local_source_stat_matches_receipt(final_source, self.receipt)
        )
        if not final_source_matches:
            return True
        if self.staging_fd is not None and self.staged_name is not None:
            self.staging_changed = self.staging_changed or (
                self.staging_mutation_monitor is None or self.staging_mutation_monitor.changed()
            )
            if self.staging_changed:
                return True
            try:
                staged_entry = os.stat(
                    self.staged_name,
                    dir_fd=self.staging_fd,
                    follow_symlinks=False,
                )
                staged_target = os.stat(self.staged_name, dir_fd=self.staging_fd)
            except OSError:
                return True
            if (
                self.staged_entry_stat is None
                or any(
                    getattr(staged_entry, field) != getattr(self.staged_entry_stat, field)
                    for field in (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                        "st_nlink",
                    )
                )
                or not os.path.samestat(final_source, staged_target)
            ):
                return True
        return False

    def close(self) -> None:
        """Release the retained directory chain exactly once."""
        if self.closed:
            return
        self.closed = True
        if self.staging_mutation_monitor is not None:
            with suppress(OSError):
                self.staging_mutation_monitor.close()
        if self.staging_fd is not None and self.staged_name is not None:
            with suppress(OSError):
                os.unlink(self.staged_name, dir_fd=self.staging_fd)
        if self.staging_fd is not None:
            with suppress(OSError):
                os.close(self.staging_fd)
        if self.staging_path is not None and self.staging_stat is not None and self.staging_parent_fd is not None:
            with suppress(OSError):
                current_staging = os.stat(
                    self.staging_path.name,
                    dir_fd=self.staging_parent_fd,
                    follow_symlinks=False,
                )
                if os.path.samestat(self.staging_stat, current_staging):
                    os.rmdir(self.staging_path.name, dir_fd=self.staging_parent_fd)
        elif self.staging_path is not None:
            with suppress(OSError):
                self.staging_path.rmdir()
        if self.staging_parent_fd is not None:
            with suppress(OSError):
                os.close(self.staging_parent_fd)
        for descriptor, _expected in reversed(self.guarded_descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _local_source_receipt_from_stat(
    resolved_path: str,
    lexical_identity: str,
    source_stat: os.stat_result,
) -> dict[str, int | str]:
    """Build the scalar source receipt shared by path and descriptor validation."""
    return {
        "resolved_path": resolved_path,
        "lexical_identity": lexical_identity,
        "device": source_stat.st_dev,
        "inode": source_stat.st_ino,
        "mode_type": stat.S_IFMT(source_stat.st_mode),
        "size": source_stat.st_size,
        "mtime_ns": source_stat.st_mtime_ns,
        "ctime_ns": source_stat.st_ctime_ns,
        "nlink": source_stat.st_nlink,
    }


def _open_bound_local_source(source_path: str | os.PathLike[str]) -> _BoundLocalSourceGuard:
    """Open and retain a POSIX root-to-source chain without a reopen gap."""
    if os.name != "posix":
        raise OSError("retained POSIX source traversal is unsupported")
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not directory_flag:
        raise OSError("retained POSIX source traversal is unsupported")

    absolute_source = Path(os.path.abspath(os.fspath(source_path)))
    parts = absolute_source.parts
    if not parts:
        raise ValueError("local source path has no components")
    directory_flags = os.O_RDONLY | directory_flag | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    opened: list[tuple[int, dict[str, int | str]]] = []
    opened_entries: list[tuple[int, str, int, dict[str, int | str]]] = []
    identity_entries: list[tuple[Path, os.stat_result]] = []
    guard: _BoundLocalSourceGuard | None = None
    current_path = Path(parts[0])
    try:
        current_fd = os.open(current_path, directory_flags)
        try:
            current_stat = os.fstat(current_fd)
        except Exception:
            os.close(current_fd)
            raise
        current_receipt = _local_source_receipt_from_stat(str(current_path), "", current_stat)
        opened.append((current_fd, current_receipt))
        identity_entries.append((current_path, current_stat))

        for index, part in enumerate(parts[1:], start=1):
            child_fd = os.open(
                part,
                source_flags if index == len(parts) - 1 else directory_flags,
                dir_fd=current_fd,
            )
            try:
                child_stat = os.fstat(child_fd)
            except Exception:
                os.close(child_fd)
                raise
            if index != len(parts) - 1 and not stat.S_ISDIR(child_stat.st_mode):
                os.close(child_fd)
                raise NotADirectoryError(str(current_path / part))
            try:
                lexical_entry_stat = os.stat(
                    part,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
                current_entry_stat = os.stat(part, dir_fd=current_fd)
            except OSError:
                os.close(child_fd)
                raise
            if not os.path.samestat(current_entry_stat, child_stat):
                os.close(child_fd)
                raise _LocalSourceBoundaryError("local source entry changed during descriptor binding")
            lexical_entry_receipt = _local_source_receipt_from_stat(
                str(current_path / part),
                "",
                lexical_entry_stat,
            )
            opened_entries.append((current_fd, part, child_fd, lexical_entry_receipt))
            current_path /= part
            current_receipt = _local_source_receipt_from_stat(str(current_path), "", child_stat)
            opened.append((child_fd, current_receipt))
            identity_entries.append((current_path, child_stat))
            current_fd = child_fd

        final_stat = os.fstat(current_fd)
        if not (stat.S_ISDIR(final_stat.st_mode) or stat.S_ISREG(final_stat.st_mode)):
            raise OSError("local source is not a regular file or directory")
        descriptor_path = ""
        for descriptor_root in _retained_descriptor_paths(current_fd):
            try:
                descriptor_stat = os.stat(descriptor_root)
            except OSError:
                continue
            if os.path.samestat(final_stat, descriptor_stat):
                descriptor_path = str(descriptor_root)
                break
        if not descriptor_path:
            raise OSError("descriptor-backed local source traversal is unavailable")

        lexical_identity = _local_source_lexical_identity(identity_entries)
        receipt = _local_source_receipt_from_stat(
            os.path.realpath(descriptor_path),
            lexical_identity,
            final_stat,
        )
        guard = _BoundLocalSourceGuard(
            bound_path=descriptor_path,
            receipt=receipt,
            guarded_descriptors=tuple(opened),
            guarded_entries=tuple(opened_entries),
        )
        if stat.S_ISREG(final_stat.st_mode):
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            staging_path = Path(tempfile.mkdtemp(prefix=".modelaudit_source_"))
            guard.staging_path = staging_path
            guard.staging_stat = os.stat(staging_path, follow_symlinks=False)
            guard.staging_parent_fd = os.open(staging_path.parent, directory_flags)
            guard.staging_fd = os.open(staging_path, directory_flags | nofollow)
            opened_staging = os.fstat(guard.staging_fd)
            effective_uid = getattr(os, "geteuid", lambda: opened_staging.st_uid)()
            if (
                not stat.S_ISDIR(opened_staging.st_mode)
                or opened_staging.st_uid != effective_uid
                or stat.S_IMODE(opened_staging.st_mode) & 0o077
                or not os.path.samestat(opened_staging, guard.staging_stat)
            ):
                raise _LocalSourceBoundaryError("private source staging directory changed while opening")
            staging_descriptor_root = ""
            for staged_descriptor_path in _retained_descriptor_paths(guard.staging_fd):
                try:
                    descriptor_stat = os.stat(staged_descriptor_path)
                except OSError:
                    continue
                if os.path.samestat(opened_staging, descriptor_stat):
                    staging_descriptor_root = str(staged_descriptor_path)
                    break
            if not staging_descriptor_root:
                raise OSError("descriptor-backed local source staging is unavailable")
            guard.staged_name = absolute_source.name
            if not guard.staged_name or guard.staged_name in {".", ".."}:
                raise _LocalSourceBoundaryError("local source omitted a safe filename")
            os.symlink(descriptor_path, guard.staged_name, dir_fd=guard.staging_fd)
            guard.staged_entry_stat = os.stat(
                guard.staged_name,
                dir_fd=guard.staging_fd,
                follow_symlinks=False,
            )
            staged_target = os.stat(guard.staged_name, dir_fd=guard.staging_fd)
            if not os.path.samestat(final_stat, staged_target):
                raise _LocalSourceBoundaryError("staged local source resolved to a different file")
            guard.staging_mutation_monitor = _StagingMutationMonitor.arm((guard.staging_fd,))
            guard.bound_path = str(Path(staging_descriptor_root) / guard.staged_name)
        if guard.changed():
            raise _LocalSourceBoundaryError("local source changed during descriptor binding")
        return guard
    except Exception:
        if guard is not None:
            guard.close()
            opened.clear()
        for descriptor, _expected in reversed(opened):
            with suppress(OSError):
                os.close(descriptor)
        raise


@contextmanager
def _bound_local_source_directory(
    source_path: str | os.PathLike[str],
    expected_receipt: dict[str, int | str],
) -> Iterator[str]:
    """Yield a descriptor-backed POSIX directory captured by a dispatch receipt."""
    resolved_path = expected_receipt.get("resolved_path")
    if not isinstance(resolved_path, str):
        raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
    if os.name != "posix":
        yield resolved_path
        return
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    source_descriptor = os.open(source_path, directory_flags)
    try:
        bound_stat = os.fstat(source_descriptor)
        if not _local_source_stat_matches_receipt(bound_stat, expected_receipt):
            raise _LocalSourceBoundaryError("local source changed before descriptor binding")
        for descriptor_root in _retained_descriptor_paths(source_descriptor):
            try:
                descriptor_stat = descriptor_root.stat()
            except OSError:
                continue
            if _local_source_stat_matches_receipt(descriptor_stat, expected_receipt):
                yield str(descriptor_root)
                return
        raise _LocalSourceBoundaryError("descriptor-backed local source traversal is unavailable")
    finally:
        os.close(source_descriptor)


def _map_nested_source_value(value: Any, transform: Callable[[str], str]) -> Any:
    """Apply one path transform across scanner-owned nested values."""
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, os.PathLike):
        return transform(os.fspath(value))
    if isinstance(value, dict):
        return {
            _map_nested_source_value(key, transform): _map_nested_source_value(item, transform)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_map_nested_source_value(item, transform) for item in value]
    if isinstance(value, tuple):
        return tuple(_map_nested_source_value(item, transform) for item in value)
    if isinstance(value, set):
        return {_map_nested_source_value(item, transform) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_map_nested_source_value(item, transform) for item in value)
    return value


def _rebase_local_source_value(value: Any, source_roots: tuple[str, ...], report_root: str) -> Any:
    """Rewrite descriptor or resolved source paths to the requested lexical root."""

    def rebase(source_value: str) -> str:
        for source_root in source_roots:
            if source_root and source_root != report_root:
                source_value = source_value.replace(source_root, report_root)
        return re.sub(
            r"(?:/proc/(?:self|\d+)/fd|/dev/fd)/\d+",
            lambda _match: report_root,
            source_value,
        )

    return _map_nested_source_value(value, rebase)


def _local_source_logical_path(
    path: str | os.PathLike[str],
    bound_root: str | None,
    resolved_root: str | None,
) -> Path:
    """Map a descriptor-backed member to its stable resolved-root spelling."""
    path_obj = Path(path)
    if bound_root is None or resolved_root is None:
        return path_obj
    try:
        relative_path = Path(os.path.abspath(path_obj)).relative_to(Path(os.path.abspath(bound_root)))
    except ValueError:
        return path_obj
    return Path(resolved_root).joinpath(*relative_path.parts)


def _rebase_local_source_result(
    results: ModelAuditResultModel,
    bound_root: str,
    resolved_root: str,
    report_root: str,
) -> ModelAuditResultModel:
    """Remove descriptor-only paths from a local source result."""
    rebased = _rebase_local_source_value(
        results.model_dump(mode="python"),
        (bound_root, resolved_root),
        report_root,
    )
    return ModelAuditResultModel.model_validate(rebased)


def _rebase_local_source_descendants(
    value: Any,
    source_root: str,
    target_root: str,
) -> Any:
    """Map descendants while preserving the selected top-level source spelling."""

    def rebase_descendant(source_value: str) -> str:
        source_prefix = source_root.rstrip(os.sep) + os.sep
        if source_value.startswith(source_prefix):
            return target_root.rstrip(os.sep) + os.sep + source_value[len(source_prefix) :]
        return source_value

    return _map_nested_source_value(value, rebase_descendant)


def _rebase_symlinked_local_source_directory_descendants(
    results: ModelAuditResultModel,
    report_root: str,
    resolved_root: str,
) -> ModelAuditResultModel:
    """Preserve legacy resolved child paths below a lexical directory symlink."""
    rebased = _rebase_local_source_descendants(
        results.model_dump(mode="python"),
        report_root,
        resolved_root,
    )
    return ModelAuditResultModel.model_validate(rebased)


def _validated_local_source_receipt(value: object) -> dict[str, int | str] | None:
    """Accept only the private scalar receipt shape used across CLI dispatch."""
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, (int, str)) for key, item in value.items()
    ):
        return None
    return dict(value)


@contextmanager
def _retain_windows_local_source_guards(
    source_path: str | os.PathLike[str],
    expected_receipt: dict[str, int | str],
) -> Iterator[None]:
    """Deny replacement of a validated Windows source and its reparse chain."""
    if os.name != "nt":
        yield
        return

    import ctypes
    import ctypes.wintypes as wintypes

    ctypes_windows: Any = ctypes
    kernel32 = ctypes_windows.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    guard_paths: list[tuple[Path, bool]] = []
    for entry_path, entry_stat in _local_source_lexical_identity_entries(source_path):
        is_reparse_point = stat.S_ISLNK(entry_stat.st_mode) or _stat_is_windows_reparse_point(entry_stat)
        guard_paths.append((entry_path, is_reparse_point))
    resolved_path = expected_receipt.get("resolved_path")
    if not isinstance(resolved_path, str):
        raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
    guard_paths.append((Path(resolved_path), False))

    handles: list[int] = []
    invalid_handle_value = ctypes.c_void_p(-1).value
    try:
        for guard_path, open_reparse_point in dict.fromkeys(guard_paths):
            flags = 0x02000000 | (0x00200000 if open_reparse_point else 0)
            handle = create_file(
                str(guard_path),
                0,
                0x00000001,
                None,
                3,
                flags,
                None,
            )
            if handle in (None, invalid_handle_value):
                raise ctypes_windows.WinError(ctypes_windows.get_last_error())
            handles.append(handle if isinstance(handle, int) else int(handle.value))
        if not _local_source_receipts_match(expected_receipt, _snapshot_local_source_receipt(source_path)):
            raise _LocalSourceBoundaryError("local source changed while retaining its boundary")
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


def _record_local_source_boundary_failure(results: ModelAuditResultModel, source_path: FilePath) -> None:
    """Record one fail-closed local dispatch boundary result."""
    report_path = _redacted_scan_path_for_reporting(source_path)
    results.has_errors = True
    results.success = False
    results.content_hash = None
    if any(
        check.name == "Local Source Boundary Check"
        and check.details.get("reason") == "local_source_changed_during_scan"
        for check in results.checks
    ):
        return
    results.checks.append(
        Check(
            name="Local Source Boundary Check",
            status=CheckStatus.FAILED,
            message="Validated local source changed during scan dispatch; scan coverage is incomplete.",
            severity=IssueSeverity.INFO,
            location=report_path,
            details={
                "path": report_path,
                "reason": "local_source_changed_during_scan",
                "analysis_incomplete": True,
                "operational_error": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "source_boundary_changed",
            },
        )
    )


def _local_source_boundary_failure_scan_result(source_path: str, error: Exception | None = None) -> ScanResult:
    """Return a path-specific operational failure for an unpinnable local source."""
    result = ScanResult(scanner_name="local_source_boundary")
    details: dict[str, Any] = {
        "path": source_path,
        "reason": "local_source_changed_during_scan",
        "analysis_incomplete": True,
        "operational_error": True,
        "scan_outcome": "inconclusive",
        "scan_outcome_reason": "source_boundary_changed",
    }
    if error is not None:
        details["exception_type"] = type(error).__name__
    result.add_check(
        name="Local Source Boundary Check",
        passed=False,
        message="Validated local source changed during scan dispatch; scan coverage is incomplete.",
        severity=IssueSeverity.INFO,
        location=source_path,
        details=details,
    )
    _mark_operational_scan_error(result, "source_boundary_changed")
    _mark_inconclusive_scan_outcome(result, "source_boundary_changed")
    result.finish(success=False)
    return result


def _max_file_size_failure_scan_result(source_path: str, file_size: int, max_file_size: int) -> ScanResult:
    """Return a bounded operational result without opening oversized staged content."""
    result = ScanResult(scanner_name="size_check")
    result.add_check(
        name="File Size Limit Check",
        passed=False,
        message=f"File too large to scan: {file_size} bytes (max: {max_file_size})",
        severity=IssueSeverity.INFO,
        location=source_path,
        details={
            "file_size": file_size,
            "max_file_size": max_file_size,
            "path": source_path,
            "analysis_incomplete": True,
        },
    )
    _mark_operational_scan_error(result, "max_file_size_exceeded")
    _mark_inconclusive_scan_outcome(result, "max_file_size_exceeded")
    result.finish(success=False)
    return result


def _max_total_size_failure_scan_result(source_path: str, projected_total: int, max_total_size: int) -> ScanResult:
    """Return an operational result before a private copy would exceed the aggregate cap."""
    result = ScanResult(scanner_name="size_check")
    result.add_check(
        name="Total Scan Size Limit Check",
        passed=False,
        message=f"Total scan size limit exceeded: {projected_total} bytes (max: {max_total_size})",
        severity=IssueSeverity.INFO,
        location=source_path,
        details={
            "max_total_size": max_total_size,
            "projected_total_size": projected_total,
            "analysis_incomplete": True,
        },
    )
    _mark_operational_scan_error(result, "max_total_size_exceeded")
    _mark_inconclusive_scan_outcome(result, "max_total_size_exceeded")
    result.finish(success=False)
    return result


def _local_source_receipts_match(
    expected: dict[str, int | str],
    current: dict[str, int | str] | None,
) -> bool:
    """Return whether a source still names the object captured at dispatch."""
    if current is None or expected.keys() != current.keys():
        return False
    for field, expected_value in expected.items():
        current_value = current.get(field)
        if field == "resolved_path" and isinstance(expected_value, str) and isinstance(current_value, str):
            if os.path.normcase(os.path.normpath(expected_value)) != os.path.normcase(os.path.normpath(current_value)):
                return False
        elif current_value != expected_value:
            return False
    return True


_WindowsShardGuards = list[tuple[int, str, dict[str, int | str]]]


def _retain_windows_shard_guard(
    guards: _WindowsShardGuards,
    resolved_path: str,
    source_path: str,
    target: dict[str, int | str],
) -> None:
    """Retain one write-denying Windows shard handle through reconciliation."""
    if os.name != "nt":
        return
    guard_fd: int | None = None
    try:
        guard_fd = _open_windows_shard_guard_fd(resolved_path)
        if not _validated_stat_matches_target(os.fstat(guard_fd), target):
            raise _ShardPinUnavailableError("validated shard changed before terminal guarding")
        guards.append((guard_fd, source_path, dict(target)))
        guard_fd = None
    finally:
        if guard_fd is not None:
            os.close(guard_fd)


def _windows_shard_guard_is_stable(guard_fd: int, target: dict[str, int | str]) -> bool:
    try:
        return _validated_stat_matches_target(os.fstat(guard_fd), target)
    except OSError:
        return False


def _close_windows_shard_guards(guards: _WindowsShardGuards) -> None:
    for guard_fd, _source_path, _target in reversed(guards):
        with suppress(OSError):
            os.close(guard_fd)
    guards.clear()


def _rebase_prevalidated_shard_info(value: Any, source_path: str, pinned_path: str, depth: int = 0) -> Any:
    """Rebase one selected source path inside prevalidated shard metadata."""
    normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(source_path)))

    def rebase(item: Any, item_depth: int) -> Any:
        if item_depth > 8:
            return item
        if isinstance(item, str):
            normalized_item = os.path.normcase(os.path.normpath(os.path.abspath(item)))
            return pinned_path if normalized_item == normalized_source else item
        if isinstance(item, dict):
            return {rebase(key, item_depth + 1): rebase(child, item_depth + 1) for key, child in item.items()}
        if isinstance(item, list):
            return [rebase(child, item_depth + 1) for child in item]
        if isinstance(item, tuple):
            return tuple(rebase(child, item_depth + 1) for child in item)
        return item

    return rebase(value, depth)


def _openvino_weights_companion_owner(path: Path) -> Path | None:
    """Return the OpenVINO XML that owns a same-stem .bin sidecar."""
    try:
        from modelaudit.scanners.openvino_scanner import openvino_xml_companion_for_weights

        return openvino_xml_companion_for_weights(path)
    except Exception:
        return None


def _is_openvino_xml_path(path: Path) -> bool:
    """Return whether the path is a local OpenVINO XML model."""
    if path.suffix.lower() != ".xml":
        return False
    try:
        from modelaudit.scanners.openvino_scanner import OpenVinoScanner

        return OpenVinoScanner.can_handle(str(path))
    except Exception:
        return False


def _is_streamed_onnx_external_data_hash_candidate(path: Path) -> bool:
    """Return whether a streamed path may declare ONNX external_data sidecars."""
    if path.suffix.lower() == ".onnx":
        return True
    try:
        return detect_file_format_for_skip_filter(str(path)) == "onnx"
    except (OSError, RuntimeError, ValueError):
        return False


def _streamed_onnx_external_data_hash_paths(
    path: Path,
    *,
    deadline: float | None = None,
) -> list[Path] | None:
    """Return safe ONNX sidecars, or ``None`` when discovery cannot complete."""
    if not _is_streamed_onnx_external_data_hash_candidate(path):
        return []

    def check_discovery_interrupted() -> None:
        check_interrupted()
        if deadline is not None and time.time() > deadline:
            raise TimeoutError("ONNX external_data discovery exceeded the scan deadline")

    try:
        import onnx

        from modelaudit.scanners.onnx_scanner import (
            _is_trusted_huggingface_cache_external_alias,
            _is_windows_absolute_path,
            _iter_model_external_data_tensor_groups,
            _load_onnx_structure_file_backed,
            _OnnxStructureParseError,
            _resolve_external_location,
            _resolve_external_location_lexically,
        )
    except Exception:
        return []

    try:
        model_path = Path(os.path.abspath(path))
        source_stat = os.stat(model_path)
        model, _ = _load_onnx_structure_file_backed(
            str(model_path),
            source_stat.st_size,
            check_discovery_interrupted,
            expected_stat=source_stat,
        )
    except TimeoutError:
        raise
    except _OnnxStructureParseError:
        return None
    except Exception:
        return []

    model_dir = model_path.parent
    lexical_model_dir = Path(os.path.abspath(model_dir))
    try:
        resolved_model_dir = model_dir.resolve()
    except OSError:
        return []

    external_paths: list[Path] = []
    seen_external_paths: set[Path] = set()
    for tensors in _iter_model_external_data_tensor_groups(model, check_discovery_interrupted):
        for tensor in tensors:
            if getattr(tensor, "data_location", None) != onnx.TensorProto.EXTERNAL:
                continue
            if not getattr(tensor, "external_data", ()):
                continue
            info: dict[str, str] = {}
            for entry in tensor.external_data:
                check_discovery_interrupted()
                info[entry.key] = entry.value
            location = info.get("location")
            if (
                not isinstance(location, str)
                or not location
                or "\x00" in location
                or _is_windows_absolute_path(location)
            ):
                continue

            lexical_external_path = _resolve_external_location_lexically(model_dir, location)
            try:
                lexical_external_path.relative_to(lexical_model_dir)
            except ValueError:
                continue

            external_path = _resolve_external_location(model_dir, location)
            external_hash_path = external_path
            if not is_within_directory(str(resolved_model_dir), str(external_path)):
                if not _is_trusted_huggingface_cache_external_alias(
                    model_path,
                    lexical_external_path,
                    external_path,
                ):
                    continue
                external_hash_path = lexical_external_path
            if not external_hash_path.is_file():
                continue
            if external_path in seen_external_paths:
                continue
            seen_external_paths.add(external_path)
            external_paths.append(external_hash_path)

    return external_paths


def _openvino_xml_companion_key(path: Path) -> str:
    """Return a stable lexical key for one scheduled OpenVINO XML scan."""
    return os.path.normcase(os.path.normpath(str(Path(os.path.abspath(path)))))


def _with_openvino_scanned_xml_companion(config: dict[str, Any], xml_path: Path) -> dict[str, Any]:
    """Record an OpenVINO XML that will cover its same-stem weights sidecar."""
    configured_companions = config.get(_OPENVINO_SCANNED_XML_COMPANIONS_CONFIG_KEY, ())
    companion_keys = {
        str(companion_key) for companion_key in configured_companions if isinstance(companion_key, (str, Path))
    }
    companion_keys.add(_openvino_xml_companion_key(xml_path))
    updated_config = dict(config)
    updated_config[_OPENVINO_SCANNED_XML_COMPANIONS_CONFIG_KEY] = tuple(sorted(companion_keys))
    return updated_config


def _openvino_xml_companion_will_be_scanned(xml_path: Path, config: dict[str, Any]) -> bool:
    """Return whether this scan invocation scheduled the owning XML through OpenVINO."""
    if not policy_from_config(config).allows("openvino"):
        return False
    configured_companions = config.get(_OPENVINO_SCANNED_XML_COMPANIONS_CONFIG_KEY, ())
    if not isinstance(configured_companions, (list, tuple, set, frozenset)):
        return False
    return _openvino_xml_companion_key(xml_path) in {
        str(companion_key) for companion_key in configured_companions if isinstance(companion_key, (str, Path))
    }


def _snapshot_file_identity(path: Path) -> _FileIdentitySnapshot | None:
    """Snapshot path and target identity for TOCTOU-sensitive companion checks."""
    try:
        link_stat = os.lstat(path)
    except OSError:
        return None

    stat_fields: tuple[int, int, int, int, int, int] | None = None
    resolved_path: str | None = None
    try:
        target_stat = os.stat(path)
        stat_fields = (
            target_stat.st_dev,
            target_stat.st_ino,
            target_stat.st_mode,
            target_stat.st_size,
            target_stat.st_mtime_ns,
            target_stat.st_ctime_ns,
        )
        resolved_path = str(path.resolve(strict=True))
    except OSError:
        # TOCTOU races or inaccessible symlink targets still leave a useful lstat snapshot.
        logger.debug("Could not snapshot target identity for %s", path, exc_info=True)

    return _FileIdentitySnapshot(
        lstat=(
            link_stat.st_dev,
            link_stat.st_ino,
            link_stat.st_mode,
            link_stat.st_size,
            link_stat.st_mtime_ns,
            link_stat.st_ctime_ns,
        ),
        stat=stat_fields,
        resolved_path=resolved_path,
    )


def _file_target_identity_key(
    path: Path,
    snapshot: _FileIdentitySnapshot | None,
) -> _FileTargetIdentityKey | None:
    """Return a target-oriented key that is stable across symlink aliases."""
    if snapshot is None:
        return None
    if snapshot.stat is not None:
        return ("stat", *snapshot.stat)
    return (
        "path",
        os.path.normcase(os.path.normpath(str(Path(os.path.abspath(path))))),
        *snapshot.lstat,
    )


def _snapshot_file_size(snapshot: _FileIdentitySnapshot | None) -> int:
    """Return the target size captured by a file identity snapshot."""
    if snapshot is None:
        return 0
    stat_fields = snapshot.stat or snapshot.lstat
    return stat_fields[3]


def _openvino_xml_weights_companion(path: Path) -> Path | None:
    """Return a local OpenVINO XML model's same-stem weights sidecar."""
    if not _is_openvino_xml_path(path):
        return None
    try:
        from modelaudit.scanners.openvino_scanner import openvino_weights_companion_for_xml

        return openvino_weights_companion_for_xml(path)
    except Exception:
        return None


def _openvino_weights_symlink_escape(xml_path: Path, companion_path: Path) -> Path | None:
    """Return an escaped OpenVINO weights target while preserving lexical symlink evidence."""
    if not companion_path.is_symlink():
        return None
    try:
        model_dir = xml_path.resolve(strict=True).parent
        resolved_companion = companion_path.resolve(strict=False)
    except (OSError, RuntimeError):
        return Path(os.path.realpath(companion_path))
    if is_within_directory(str(model_dir), str(resolved_companion)):
        return None
    return resolved_companion


def _openvino_weights_symlink_escape_result(
    xml_path: Path,
    companion_path: Path,
    resolved_companion: Path,
) -> ScanResult:
    """Represent an escaped lexical sidecar without reopening it through a staged copy."""
    result = ScanResult(scanner_name="openvino")
    result.add_check(
        name="OpenVINO Weights Symlink Boundary Check",
        passed=False,
        message="Associated .bin weights file resolves outside the model directory",
        severity=IssueSeverity.CRITICAL,
        location=str(companion_path),
        details={
            "expected_file": str(companion_path),
            "resolved_path": str(resolved_companion),
            "model_directory": os.path.realpath(xml_path.parent),
            "cwe": "CWE-22",
        },
        rule_code="S701",
        why=(
            "OpenVINO sidecar weights are loaded from the .bin file adjacent to the XML. "
            "A symlinked sidecar can make model loading read data outside the model directory."
        ),
    )
    result.finish(success=False)
    return result


def _mxnet_companion_paths(path: Path) -> tuple[Path, ...]:
    """Return same-directory MXNet symbol/params companions used for path-sensitive metadata."""
    symbol_suffix = "-symbol.json"
    if path.name.lower().endswith(symbol_suffix):
        prefix = path.name[: -len(symbol_suffix)]
        candidates: list[Path] = []
        for candidate in path.parent.glob(f"{prefix}-*.params"):
            match = re.fullmatch(r"(?P<prefix>.+)-(?P<epoch>\d{1,8})\.params", candidate.name, re.IGNORECASE)
            if match is not None and match.group("prefix") == prefix:
                candidates.append(candidate)
        return tuple(sorted(candidates))

    params_match = re.fullmatch(r"(?P<prefix>.+)-(?P<epoch>\d{1,8})\.params", path.name, re.IGNORECASE)
    if params_match is None:
        return ()
    symbol_path = path.with_name(f"{params_match.group('prefix')}{symbol_suffix}")
    return (symbol_path,) if symbol_path.is_file() else ()


def _oci_manifest_layer_companion_paths(path: Path) -> tuple[Path, ...]:
    """Return bounded local OCI layer references that must accompany one manifest scan."""
    try:
        from modelaudit.scanners import oci_layer_scanner

        scanner_class = oci_layer_scanner.OciLayerScanner
        if not scanner_class.can_handle(str(path)):
            return ()
        if path.stat().st_size > scanner_class.default_max_file_read_size:
            return ()
        manifest_text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            manifest_data: Any = json.loads(manifest_text)
        except Exception:
            if not oci_layer_scanner.HAS_YAML:
                return ()
            manifest_data = oci_layer_scanner.yaml.safe_load(manifest_text)
    except Exception:
        return ()

    companions: list[Path] = []
    for layer_ref in scanner_class._collect_layer_paths(manifest_data):
        normalized_ref = scanner_class._normalize_layer_ref(layer_ref)
        if scanner_class._is_remote_layer_ref(normalized_ref):
            continue
        candidate = path.parent / normalized_ref
        try:
            resolved_candidate = candidate.resolve(strict=True)
            resolved_parent = path.parent.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate.is_file() and is_within_directory(str(resolved_parent), str(resolved_candidate)):
            companions.append(candidate)
    return tuple(dict.fromkeys(companions))


def _snapshot_openvino_companion_for_hash(xml_path: Path, companion_path: Path) -> _FileIdentitySnapshot | None:
    """Snapshot an OpenVINO sidecar only when hashing stays in the model directory."""
    companion_snapshot = _snapshot_file_identity(companion_path)
    if companion_snapshot is None:
        return None
    if not companion_path.is_symlink():
        return companion_snapshot

    try:
        model_dir = xml_path.resolve(strict=True).parent
    except OSError:
        return None
    if companion_snapshot.resolved_path is None or not is_within_directory(
        str(model_dir),
        companion_snapshot.resolved_path,
    ):
        return None
    return companion_snapshot


def _openvino_weights_sidecar_needs_independent_scan(
    path: Path,
    scanner_selection: ScannerSelectionPolicy,
) -> bool:
    """Return whether an OpenVINO weights sidecar has trusted non-OpenVINO content routing."""
    if path.suffix.lower() != ".bin" or not path.is_file():
        return False

    try:
        magic_format = detect_file_format_from_magic(str(path))
    except Exception:
        magic_format = "unknown"

    if magic_format in {"zip", EXECUTABLE_ZIP_POLYGLOT_FORMAT} and allows_zip_structure_analysis(
        scanner_selection,
        str(path),
    ):
        return True

    try:
        supplemental_scanner_id = detect_pytorch_binary_supplemental_format(str(path))
    except Exception:
        return False
    return supplemental_scanner_id is not None and scanner_selection.allows(supplemental_scanner_id)


def _validated_shard_family_scopes(
    source_path: str,
    target: dict[str, int | str],
) -> set[str]:
    """Return validated scopes that may identify one shard family."""
    parent = Path(source_path).absolute().parent
    normalized_parent = os.path.normcase(os.path.normpath(str(parent)))
    scopes = {f"directory:{normalized_parent}"}
    family_group = target.get("family_group")
    if isinstance(family_group, str) and family_group:
        scopes.add(f"trusted-group:{family_group}")
    authoritative_index_path = target.get("authoritative_shard_index_path")
    authoritative_index_fingerprint = target.get("authoritative_shard_index_fingerprint")
    authoritative_index_generation = target.get("authoritative_shard_index_generation")
    if (
        isinstance(authoritative_index_path, str)
        and target.get("authoritative_shard_index_base") in {"zero", "one"}
        and isinstance(authoritative_index_fingerprint, str)
        and authoritative_index_fingerprint
        and isinstance(authoritative_index_generation, int)
        and not isinstance(authoritative_index_generation, bool)
        and authoritative_index_generation > 0
    ):
        scopes.add(f"validated-index:{authoritative_index_path}")
    return scopes


def _group_validated_shard_family_targets(
    validated_targets: ValidatedShardTargets,
) -> dict[tuple[str, int, str], dict[int, list[tuple[str, dict[str, int | str]]]]]:
    """Group validated shard records by pattern, declared total, and trusted scope."""
    grouped_targets: dict[
        tuple[str, int, str],
        dict[int, list[tuple[str, dict[str, int | str]]]],
    ] = {}
    for source_path, target in validated_targets.items():
        shard_match = ShardedModelDetector.match_shard_filename(Path(source_path).name)
        if shard_match is None:
            continue
        pattern = shard_match.get("pattern")
        shard_index = shard_match.get("current_shard_index")
        expected_total = shard_match.get("expected_total_shards")
        if (
            not isinstance(pattern, str)
            or not isinstance(shard_index, int)
            or not isinstance(expected_total, int)
            or expected_total <= 0
        ):
            continue
        for family_scope in _validated_shard_family_scopes(source_path, target):
            grouped_targets.setdefault((pattern, expected_total, family_scope), {}).setdefault(shard_index, []).append(
                (source_path, target)
            )
    return grouped_targets


def _authoritative_shard_indices_for_group(
    expected_total: int,
    targets_by_index: dict[int, list[tuple[str, dict[str, int | str]]]],
) -> tuple[range | None, bool]:
    """Return consistent index authority and whether any target claimed it."""
    proofs: set[tuple[str, str, str, int]] = set()
    authority_present = False
    missing_proof = False
    for records in targets_by_index.values():
        for _source_path, target in records:
            index_base = target.get("authoritative_shard_index_base")
            index_path = target.get("authoritative_shard_index_path")
            index_fingerprint = target.get("authoritative_shard_index_fingerprint")
            index_generation = target.get("authoritative_shard_index_generation")
            if all(value is None for value in (index_base, index_path, index_fingerprint, index_generation)):
                missing_proof = True
                continue
            authority_present = True
            if (
                not isinstance(index_base, str)
                or index_base not in {"zero", "one"}
                or not isinstance(index_path, str)
                or not index_path
                or not isinstance(index_fingerprint, str)
                or not index_fingerprint
                or not isinstance(index_generation, int)
                or isinstance(index_generation, bool)
                or index_generation <= 0
            ):
                return None, True
            proofs.add((index_base, index_path, index_fingerprint, index_generation))
    if not authority_present:
        return None, False
    if missing_proof or len(proofs) != 1:
        return None, True
    index_base, _index_path, _index_fingerprint, _index_generation = next(iter(proofs))
    return ShardedModelDetector._expected_index_range(expected_total, zero_based=index_base == "zero"), True


def _complete_validated_shard_family_sources(validated_targets: ValidatedShardTargets) -> set[str]:
    """Return source paths belonging to complete, uniquely targeted shard families."""
    grouped_targets = _group_validated_shard_family_targets(validated_targets)

    complete_sources: set[str] = set()
    for (_pattern, expected_total, _family_scope), targets_by_index in grouped_targets.items():
        authoritative_indices, authority_present = _authoritative_shard_indices_for_group(
            expected_total,
            targets_by_index,
        )
        if authority_present and authoritative_indices is None:
            continue
        expected_indices, _index_base = ShardedModelDetector.expected_indices_for_shard_family(
            expected_total,
            authoritative_indices=authoritative_indices,
        )
        if len(targets_by_index) != _count_expected_shard_indices(expected_indices):
            continue
        if any(index not in expected_indices for index in targets_by_index):
            continue
        if any(len(records) != 1 for records in targets_by_index.values()):
            continue
        records = [records[0] for records in targets_by_index.values()]

        inode_targets: dict[tuple[int, int], list[dict[str, int | str]]] = {}
        path_identities: set[str] = set()
        duplicate_target = False
        for _source_path, target in records:
            inode = target.get("inode")
            device = target.get("device")
            resolved_target = target.get("resolved_path")
            if isinstance(inode, int) and inode and isinstance(device, int):
                inode_key = (device, inode)
                for existing_target in inode_targets.get(inode_key, []):
                    existing_path = existing_target.get("resolved_path")
                    same_resolved_path = (
                        isinstance(existing_path, str)
                        and isinstance(resolved_target, str)
                        and os.path.normcase(os.path.normpath(existing_path))
                        == os.path.normcase(os.path.normpath(resolved_target))
                    )
                    hardlink_observed = any(
                        isinstance((link_count := candidate.get("nlink")), int) and link_count > 1
                        for candidate in (existing_target, target)
                    )
                    generation_fields = ("size", "mtime_ns", "ctime_ns")
                    generations_available = all(
                        isinstance(candidate.get(field), int)
                        for candidate in (existing_target, target)
                        for field in generation_fields
                    )
                    same_generation = generations_available and all(
                        existing_target[field] == target[field] for field in generation_fields
                    )
                    if same_resolved_path or hardlink_observed or same_generation or not generations_available:
                        duplicate_target = True
                        break
                if duplicate_target:
                    break
                inode_targets.setdefault(inode_key, []).append(target)
            elif isinstance(resolved_target, str):
                path_identity = os.path.normcase(os.path.normpath(resolved_target))
                if path_identity in path_identities:
                    duplicate_target = True
                    break
                path_identities.add(path_identity)
            else:
                duplicate_target = True
                break
        if duplicate_target:
            continue

        complete_sources.update(
            os.path.normcase(os.path.normpath(os.path.abspath(source_path))) for source_path, _target in records
        )
    return complete_sources


def _record_unexpected_validated_shard_families(
    results: ModelAuditResultModel,
    validated_targets: ValidatedShardTargets,
) -> bool:
    """Persist explicit incomplete outcomes for invalid validated shard families."""
    from .models import FileMetadataModel

    grouped_targets = _group_validated_shard_family_targets(validated_targets)
    existing_locations = {
        os.path.normcase(os.path.normpath(os.path.abspath(check.location)))
        for check in results.checks
        if check.name == "Sharded Model Coverage Check"
        and isinstance(check.location, str)
        and isinstance(check.details, dict)
        and check.details.get("scan_outcome_reason") == "unexpected_model_shards"
    }
    recorded = False
    seen_locations: set[str] = set()
    for (_pattern, expected_total, _family_scope), targets_by_index in grouped_targets.items():
        authoritative_indices, authority_present = _authoritative_shard_indices_for_group(
            expected_total,
            targets_by_index,
        )
        expected_indices, _index_base = ShardedModelDetector.expected_indices_for_shard_family(
            expected_total,
            authoritative_indices=authoritative_indices,
        )
        if authority_present and authoritative_indices is None:
            unexpected_sources = tuple(
                sorted(source_path for records in targets_by_index.values() for source_path, _target in records)
            )
        else:
            unexpected_sources = tuple(
                sorted(
                    source_path
                    for shard_index, records in targets_by_index.items()
                    for source_path, _target in (records if shard_index not in expected_indices else records[1:])
                )
            )
        if not unexpected_sources:
            continue
        sources = tuple(
            sorted(source_path for records in targets_by_index.values() for source_path, _target in records)
        )
        location = sources[0]
        normalized_location = os.path.normcase(os.path.normpath(os.path.abspath(location)))
        if normalized_location in seen_locations:
            continue
        seen_locations.add(normalized_location)
        if normalized_location not in existing_locations:
            results.checks.append(
                Check(
                    name="Sharded Model Coverage Check",
                    status=CheckStatus.FAILED,
                    message=(
                        f"Found {len(unexpected_sources)} model shard(s) outside the expected family inventory; "
                        "scan coverage is incomplete."
                    ),
                    severity=IssueSeverity.INFO,
                    location=location,
                    details={
                        "expected_total_shards": expected_total,
                        "present_total_shards": len(sources),
                        "unexpected_shard_count": len(unexpected_sources),
                        "unexpected_shards": list(unexpected_sources),
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "unexpected_model_shards",
                    },
                )
            )
            existing_locations.add(normalized_location)
            recorded = True
        for source_path in sources:
            metadata = (
                results.file_metadata[source_path].model_dump(mode="python")
                if source_path in results.file_metadata
                else {}
            )
            metadata["analysis_incomplete"] = True
            metadata["scan_outcome"] = "inconclusive"
            reasons = metadata.get("scan_outcome_reasons")
            reason_list = list(reasons) if isinstance(reasons, list) else []
            if "unexpected_model_shards" not in reason_list:
                reason_list.append("unexpected_model_shards")
            metadata["scan_outcome_reasons"] = reason_list
            metadata["scan_outcome_reason"] = "unexpected_model_shards"
            results.file_metadata[source_path] = FileMetadataModel(**metadata)
            recorded = True
    if recorded:
        results.has_errors = True
        results.success = False
    return recorded


def _scan_selected_safetensors_overlap(
    path: str,
    config: dict[str, Any],
    scanner_selection: ScannerSelectionPolicy,
    scanner_ids: frozenset[str],
) -> ScanResult | None:
    """Prefer a validated SafeTensors route when explicit selection excludes an ambiguous owner."""
    if (
        "safetensors" not in scanner_ids
        or not scanner_selection.active
        or not scanner_selection.allows("safetensors")
        or scanner_selection.allows("pickle")
    ):
        return None
    scanner_class = _registry.load_scanner_by_id("safetensors")
    if scanner_class is None:
        return None
    result = scanner_class(config=config).scan(path)
    merge_safetensors_overlap_analysis(
        path,
        result,
        config,
        scanner_selection,
        scanner_ids,
    )
    return result


def _ensure_streamed_shard_coverage_placeholder(scan_result: ScanResult, source_path: Path) -> None:
    """Record the per-file shard gap that trusted cross-file reconciliation may later disprove."""
    for record in itertools.chain(scan_result.checks, scan_result.issues):
        details = getattr(record, "details", None)
        if isinstance(details, dict) and details.get("scan_outcome_reason") == "missing_model_shards":
            return

    shard_match = ShardedModelDetector.match_shard_filename(source_path.name)
    if shard_match is None:
        return
    shard_index = shard_match.get("current_shard_index")
    expected_total = shard_match.get("expected_total_shards")
    if not isinstance(shard_index, int) or not isinstance(expected_total, int) or expected_total <= 0:
        return

    pattern = shard_match.get("pattern")
    if not isinstance(pattern, str):
        return
    expected_indices, _index_base = ShardedModelDetector.expected_indices_for_shard_family(
        expected_total,
    )
    if shard_index not in expected_indices:
        return
    missing_count = _count_expected_shard_indices(expected_indices) - 1
    if missing_count <= 0:
        return
    missing_indices = list(
        itertools.islice(
            (index for index in expected_indices if index != shard_index), MAX_RECORDED_MISSING_SHARD_INDICES
        )
    )
    _mark_inconclusive_scan_outcome(scan_result, "missing_model_shards")
    scan_result.add_check(
        name="Sharded Model Coverage Check",
        passed=False,
        message=f"Missing {missing_count} expected model shard(s); scan coverage is incomplete.",
        severity=IssueSeverity.INFO,
        location=str(source_path),
        details={
            "expected_total_shards": expected_total,
            "present_total_shards": 1,
            "missing_shard_count": missing_count,
            "missing_shard_indices": missing_indices,
            "missing_shard_indices_truncated": missing_count > len(missing_indices),
            "unreadable_shard_count": 0,
            "unreadable_shards": [],
            "out_of_scope_shard_count": 0,
            "out_of_scope_shards": [],
            "unvalidated_shard_count": 0,
            "unvalidated_shards": [],
            "duplicate_shard_count": 0,
            "duplicate_shards": [],
            "analysis_incomplete": True,
            "scan_outcome": "inconclusive",
            "scan_outcome_reason": "missing_model_shards",
        },
    )
    scan_result.finish(success=False)


def _remaining_shard_coverage_outcome(
    details: dict[str, Any],
    *,
    ignore_unexpected: bool = False,
) -> tuple[str, str] | None:
    """Return the next visible incomplete-coverage reason after missing peers are disproven."""
    out_of_scope_count = details.get("out_of_scope_shard_count")
    if isinstance(out_of_scope_count, int) and out_of_scope_count > 0:
        return (
            "out_of_scope_model_shards",
            f"Skipped {out_of_scope_count} model shard(s) resolving outside the direct scan directory; "
            "scan coverage is incomplete.",
        )

    unreadable_count = details.get("unreadable_shard_count")
    if isinstance(unreadable_count, int) and unreadable_count > 0:
        return (
            "unreadable_model_shards",
            f"Unable to read {unreadable_count} model shard(s); scan coverage is incomplete.",
        )

    unvalidated_count = details.get("unvalidated_shard_count")
    if isinstance(unvalidated_count, int) and unvalidated_count > 0:
        return (
            "unvalidated_model_shards",
            f"Skipped {unvalidated_count} model shard(s) outside the validated family; scan coverage is incomplete.",
        )

    duplicate_count = details.get("duplicate_shard_count")
    if isinstance(duplicate_count, int) and duplicate_count > 0:
        return (
            "duplicate_model_shard_targets",
            f"Skipped {duplicate_count} model shard name(s) resolving to duplicate targets; "
            "scan coverage is incomplete.",
        )

    unexpected_count = details.get("unexpected_shard_count")
    if not ignore_unexpected and isinstance(unexpected_count, int) and unexpected_count > 0:
        return (
            "unexpected_model_shards",
            f"Found {unexpected_count} model shard(s) outside the expected family inventory; "
            "scan coverage is incomplete.",
        )
    return None


def _update_missing_shard_coverage_record(
    record: Check | Issue,
    reason: str,
    message: str,
    *,
    removed_reasons: frozenset[str] = frozenset({"missing_model_shards"}),
) -> None:
    """Replace a disproven missing-shard outcome with a remaining coverage failure."""
    details = dict(record.details) if isinstance(record.details, dict) else {}
    for field_name in (
        "missing_shard_count",
        "missing_shard_indices",
        "missing_shard_indices_truncated",
    ):
        details.pop(field_name, None)
    existing_reasons = details.get("scan_outcome_reasons")
    if isinstance(existing_reasons, list):
        remaining_reasons = [
            existing_reason for existing_reason in existing_reasons if existing_reason not in removed_reasons
        ]
        if reason not in remaining_reasons:
            remaining_reasons.append(reason)
        details["scan_outcome_reasons"] = remaining_reasons
    details.pop("scan_outcome_message", None)
    details["scan_outcome_reason"] = reason
    record.details = details
    record.message = message


def _results_have_explicit_operational_error(results: ModelAuditResultModel) -> bool:
    """Return whether retained result evidence identifies an operational failure."""
    if any(
        bool(metadata.get("operational_error")) and not _metadata_has_coverage_only_operational_error(metadata)
        for metadata in results.file_metadata.values()
    ):
        return True
    if any(asset.type == "error" for asset in results.assets):
        return True
    records: list[Check | Issue] = [*results.checks, *results.issues]
    return any(
        isinstance(record.details, dict)
        and bool(record.details.get("operational_error"))
        and not _metadata_has_coverage_only_operational_error(record.details)
        for record in records
    )


def _results_have_retained_incomplete_outcome(results: ModelAuditResultModel) -> bool:
    """Return whether retained evidence still identifies incomplete analysis."""
    if any(
        bool(metadata.get("analysis_incomplete")) or metadata.get("scan_outcome") == "inconclusive"
        for metadata in results.file_metadata.values()
    ):
        return True
    records: list[Check | Issue] = [*results.checks, *results.issues]
    return any(
        isinstance(record.details, dict)
        and (bool(record.details.get("analysis_incomplete")) or record.details.get("scan_outcome") == "inconclusive")
        for record in records
    )


def _terminal_safetensors_shard_boundary_failures(
    validated_targets: ValidatedShardTargets,
    *,
    index_search_root: str | os.PathLike[str],
    index_inspection_context: _SafetensorsIndexInspectionContext,
    deleted_paths: Collection[str] = (),
    force_content_revalidation: bool = True,
) -> dict[str, str]:
    """Return final SafeTensors index or target changes across all shard parents."""
    normalized_deleted_paths = {os.path.normcase(os.path.normpath(os.path.abspath(path))) for path in deleted_paths}
    terminal_families: dict[tuple[Any, ...], list[str]] = {}
    expected_proofs: dict[tuple[Any, ...], tuple[str, str, str, int] | None] = {}
    failures: dict[str, str] = {}

    for source_path, expected_target in validated_targets.items():
        shard_match = ShardedModelDetector.match_safetensors_shard_filename(Path(source_path).name)
        if shard_match is None:
            continue
        expected_total = shard_match.get("expected_total_shards")
        if not isinstance(expected_total, int) or isinstance(expected_total, bool) or expected_total <= 0:
            failures[source_path] = "shard_index_changed_after_scan"
            continue
        index_base = expected_target.get("authoritative_shard_index_base")
        index_path = expected_target.get("authoritative_shard_index_path")
        index_fingerprint = expected_target.get("authoritative_shard_index_fingerprint")
        index_generation = expected_target.get("authoritative_shard_index_generation")
        expected_proof: tuple[str, str, str, int] | None = None
        if (
            isinstance(index_base, str)
            and index_base in {"zero", "one"}
            and isinstance(index_path, str)
            and index_path
            and isinstance(index_fingerprint, str)
            and index_fingerprint
            and isinstance(index_generation, int)
            and not isinstance(index_generation, bool)
            and index_generation > 0
        ):
            expected_proof = (index_base, index_path, index_fingerprint, index_generation)
            family_key: tuple[Any, ...] = ("proof", expected_total, *expected_proof)
        else:
            family_key = (
                "unindexed",
                expected_total,
                os.path.normcase(os.path.normpath(os.path.abspath(Path(source_path).parent))),
            )
        terminal_families.setdefault(family_key, []).append(source_path)
        expected_proofs[family_key] = expected_proof

    late_proof_sources: dict[tuple[int, str, str, str, int], list[str]] = {}
    for family_key, family_sources in terminal_families.items():
        expected_proof = expected_proofs[family_key]
        expected_total = family_key[1]
        assert isinstance(expected_total, int)
        refreshed_proof, authority_present = ShardedModelDetector.refresh_safetensors_index_proofs(
            family_sources,
            expected_total=expected_total,
            index_search_root=index_search_root,
            index_inspection_context=index_inspection_context,
            force_content_revalidation=force_content_revalidation,
            require_declared_files=expected_proof is None,
        )
        if expected_proof is None and refreshed_proof is not None and authority_present:
            late_proof_sources.setdefault((expected_total, *refreshed_proof), []).extend(family_sources)
            continue
        authority_stable = refreshed_proof == expected_proof and authority_present == (expected_proof is not None)
        if not authority_stable:
            for family_source in family_sources:
                failures[family_source] = "shard_index_changed_after_scan"

    for late_proof, grouped_sources in late_proof_sources.items():
        expected_total, refreshed_base, refreshed_path, refreshed_fingerprint, refreshed_generation = late_proof
        family_sources = list(dict.fromkeys(grouped_sources))
        observed_indices: set[int] = set()
        for family_source in family_sources:
            source_match = ShardedModelDetector.match_safetensors_shard_filename(Path(family_source).name)
            source_index = source_match.get("current_shard_index") if source_match is not None else None
            if not isinstance(source_index, int) or isinstance(source_index, bool):
                observed_indices.clear()
                break
            observed_indices.add(source_index)
        expected_start = 0 if refreshed_base == "zero" else 1
        late_authority_is_consistent = (
            len(family_sources) == expected_total
            and len(observed_indices) == expected_total
            and all(expected_start <= index < expected_start + expected_total for index in observed_indices)
        )
        if not late_authority_is_consistent:
            for family_source in family_sources:
                failures[family_source] = "shard_index_changed_after_scan"
            continue
        for family_source in family_sources:
            validated_targets[family_source].update(
                {
                    "authoritative_shard_index_base": refreshed_base,
                    "authoritative_shard_index_path": refreshed_path,
                    "authoritative_shard_index_fingerprint": refreshed_fingerprint,
                    "authoritative_shard_index_generation": refreshed_generation,
                }
            )

    for source_path, expected_target in validated_targets.items():
        if source_path in failures:
            continue
        normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(source_path)))
        if normalized_source in normalized_deleted_paths:
            if not os.path.lexists(source_path):
                continue
            failures[source_path] = "shard_target_recreated_after_scan"
            continue
        resolved_path = expected_target.get("resolved_path")
        current_target = _snapshot_validated_shard_target(
            source_path,
            resolved_path=resolved_path if isinstance(resolved_path, str) else None,
        )
        current_identity = current_target.get(source_path)
        if current_identity is not None and all(
            current_identity.get(field) == expected_target.get(field)
            for field in ("resolved_path", "device", "inode", "size", "mtime_ns", "ctime_ns", "nlink")
        ):
            continue
        failures[source_path] = "shard_target_changed_after_scan"

    return failures


def _reconcile_cross_directory_shard_coverage(
    results: ModelAuditResultModel,
    validated_targets: ValidatedShardTargets,
    *,
    missing_shard_errors_only: bool = False,
) -> bool:
    """Remove missing-shard outcomes, clearing errors only with explicit ownership proof."""
    complete_sources = _complete_validated_shard_family_sources(validated_targets)
    if not complete_sources:
        return _record_unexpected_validated_shard_families(results, validated_targets)

    def source_is_complete(path: str | None) -> bool:
        if not isinstance(path, str):
            return False
        normalized_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        return normalized_path in complete_sources

    def record_key(record: Check | Issue, reason: str) -> tuple[str, str] | None:
        if not source_is_complete(record.location):
            return None
        assert isinstance(record.location, str)
        normalized_location = os.path.normcase(os.path.normpath(os.path.abspath(record.location)))
        return (normalized_location, reason)

    def unexpected_paths_are_complete(details: dict[str, Any]) -> bool:
        unexpected_paths = details.get("unexpected_shards")
        return (
            isinstance(unexpected_paths, list)
            and bool(unexpected_paths)
            and all(isinstance(path, str) and source_is_complete(path) for path in unexpected_paths)
        )

    reconciled = False
    disproven_unexpected_sources: set[str] = set()
    existing_check_reasons = {
        key
        for check in results.checks
        if check.name == "Sharded Model Coverage Check"
        and isinstance(check.details, dict)
        and isinstance((reason := check.details.get("scan_outcome_reason")), str)
        and reason != "missing_model_shards"
        and (key := record_key(check, reason)) is not None
    }
    retained_checks: list[Check] = []
    for check in results.checks:
        details = check.details if isinstance(check.details, dict) else {}
        unexpected_disproven = source_is_complete(check.location) and unexpected_paths_are_complete(details)
        if details.get("scan_outcome_reason") == "unexpected_model_shards" and unexpected_disproven:
            assert isinstance(check.location, str)
            disproven_unexpected_sources.add(os.path.normcase(os.path.normpath(os.path.abspath(check.location))))
            reconciled = True
            continue
        if (
            check.name == "Sharded Model Coverage Check"
            and details.get("scan_outcome_reason") == "missing_model_shards"
            and source_is_complete(check.location)
        ):
            reconciled = True
            removed_reasons = {"missing_model_shards"}
            if unexpected_disproven:
                assert isinstance(check.location, str)
                disproven_unexpected_sources.add(os.path.normcase(os.path.normpath(os.path.abspath(check.location))))
                removed_reasons.add("unexpected_model_shards")
            replacement = _remaining_shard_coverage_outcome(details, ignore_unexpected=unexpected_disproven)
            if replacement is None:
                continue
            reason, message = replacement
            key = record_key(check, reason)
            if key in existing_check_reasons:
                continue
            _update_missing_shard_coverage_record(
                check,
                reason,
                message,
                removed_reasons=frozenset(removed_reasons),
            )
            if key is not None:
                existing_check_reasons.add(key)
        retained_checks.append(check)
    results.checks = retained_checks

    existing_issue_reasons = {
        key
        for issue in results.issues
        if isinstance(issue.details, dict)
        and isinstance((reason := issue.details.get("scan_outcome_reason")), str)
        and reason != "missing_model_shards"
        and (key := record_key(issue, reason)) is not None
    }
    retained_issues: list[Issue] = []
    for issue in results.issues:
        details = issue.details if isinstance(issue.details, dict) else {}
        unexpected_disproven = source_is_complete(issue.location) and unexpected_paths_are_complete(details)
        if details.get("scan_outcome_reason") == "unexpected_model_shards" and unexpected_disproven:
            assert isinstance(issue.location, str)
            disproven_unexpected_sources.add(os.path.normcase(os.path.normpath(os.path.abspath(issue.location))))
            reconciled = True
            continue
        if details.get("scan_outcome_reason") == "missing_model_shards" and source_is_complete(issue.location):
            reconciled = True
            removed_reasons = {"missing_model_shards"}
            if unexpected_disproven:
                assert isinstance(issue.location, str)
                disproven_unexpected_sources.add(os.path.normcase(os.path.normpath(os.path.abspath(issue.location))))
                removed_reasons.add("unexpected_model_shards")
            replacement = _remaining_shard_coverage_outcome(details, ignore_unexpected=unexpected_disproven)
            if replacement is None:
                continue
            reason, message = replacement
            key = record_key(issue, reason)
            if key in existing_issue_reasons:
                continue
            _update_missing_shard_coverage_record(
                issue,
                reason,
                message,
                removed_reasons=frozenset(removed_reasons),
            )
            if key is not None:
                existing_issue_reasons.add(key)
        retained_issues.append(issue)
    results.issues = retained_issues

    from .models import FileMetadataModel

    for source_path, metadata_model in list(results.file_metadata.items()):
        if not source_is_complete(source_path):
            continue
        metadata = metadata_model.model_dump(mode="python")
        reasons = metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            continue
        normalized_source = os.path.normcase(os.path.normpath(os.path.abspath(source_path)))
        removed_reasons = {"missing_model_shards"}
        if normalized_source in disproven_unexpected_sources:
            removed_reasons.add("unexpected_model_shards")
        if not any(reason in removed_reasons for reason in reasons):
            continue
        remaining_reasons = [reason for reason in reasons if reason not in removed_reasons]
        if remaining_reasons:
            metadata["scan_outcome_reasons"] = remaining_reasons
            if metadata.get("scan_outcome_reason") in removed_reasons:
                metadata["scan_outcome_reason"] = remaining_reasons[0]
        else:
            metadata.pop("scan_outcome_reasons", None)
            if metadata.get("scan_outcome_reason") in removed_reasons:
                metadata.pop("scan_outcome_reason", None)
            if metadata.get("scan_outcome") == "inconclusive":
                metadata.pop("scan_outcome", None)
            metadata.pop("analysis_incomplete", None)
            metadata.pop("scan_outcome_message", None)
        results.file_metadata[source_path] = FileMetadataModel(**metadata)
        reconciled = True

    recorded_unexpected = _record_unexpected_validated_shard_families(results, validated_targets)
    if reconciled or recorded_unexpected:
        had_errors = results.has_errors
        results.has_errors = _results_have_explicit_operational_error(results) or (
            had_errors and (not missing_shard_errors_only or _results_have_retained_incomplete_outcome(results))
        )
        results.success = not _results_should_be_unsuccessful(results)
    return reconciled or recorded_unexpected


def _build_shard_family_cache_fingerprint(
    shard_family_key: _ShardFamilyKey,
    scanned_file_paths: list[str],
    content_hashes: dict[str, str],
    validated_targets: ValidatedShardTargets,
) -> dict[str, Any]:
    """Fingerprint every present shard so representative cache entries stay valid."""
    _parent_dir, pattern, expected_total_shards = shard_family_key
    return {
        "pattern": pattern,
        "expected_total_shards": expected_total_shards,
        "members": [
            {
                "source_path": str(Path(scanned_file_path).absolute()),
                "path": validated_targets.get(scanned_file_path, {}).get(
                    "resolved_path",
                    _resolve_or_absolute_path(scanned_file_path),
                ),
                "device": validated_targets.get(scanned_file_path, {}).get("device"),
                "inode": validated_targets.get(scanned_file_path, {}).get("inode"),
                "size": validated_targets.get(scanned_file_path, {}).get("size"),
                "mtime_ns": validated_targets.get(scanned_file_path, {}).get("mtime_ns"),
                "ctime_ns": validated_targets.get(scanned_file_path, {}).get("ctime_ns"),
                "content_hash": content_hashes.get(scanned_file_path),
            }
            for scanned_file_path in sorted(scanned_file_paths)
        ],
    }


def _resolve_or_absolute_path(path: str) -> str:
    """Return a resolved path, preserving a stable lexical path after concurrent breakage."""
    try:
        return str(Path(path).resolve(strict=True))
    except (OSError, RuntimeError):
        return str(Path(path).absolute())


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


def _validated_shard_targets_from_config(config: dict[str, Any]) -> ValidatedShardTargets | None:
    """Return the immutable lexical shard-to-target mapping from grouped scan config."""
    fingerprint = config.get(_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY)
    if not isinstance(fingerprint, dict):
        return None
    members = fingerprint.get("members")
    if not isinstance(members, list):
        return None

    targets: ValidatedShardTargets = {}
    for member in members:
        if not isinstance(member, dict):
            continue
        source_path = member.get("source_path")
        resolved_path = member.get("path")
        if not isinstance(source_path, str) or not isinstance(resolved_path, str):
            continue
        target: dict[str, int | str] = {"resolved_path": resolved_path}
        for key in ("device", "inode", "size", "mtime_ns", "ctime_ns"):
            value = member.get(key)
            if isinstance(value, int):
                target[key] = value
        targets[source_path] = target
    return targets or None


def _shard_index_search_root_from_config(config: dict[str, Any]) -> str | None:
    """Return the explicit repository boundary for ancestor shard-index lookup."""
    root = config.get(REPOSITORY_SCAN_ROOT_CONFIG_KEY)
    return root if isinstance(root, str) and root.strip() else None


def _grouped_shard_boundary_error(
    path: str,
    allowed_paths: list[str],
    allowed_targets: ValidatedShardTargets | None = None,
) -> dict[str, Any] | None:
    """Return details when a grouped shard no longer matches its validated family."""
    if ShardedModelDetector.match_shard_filename(Path(path).name) is None:
        return None

    allowed_path_set = {
        os.path.normcase(os.path.normpath(os.path.abspath(allowed_path))) for allowed_path in allowed_paths
    }
    try:
        resolved_path = Path(path).resolve(strict=True)
        resolved_stat = os.stat(resolved_path, follow_symlinks=False)
    except (OSError, RuntimeError) as e:
        return {"path": path, "error": str(e), "reason": "shard_target_unavailable"}

    normalized_resolved_path = os.path.normcase(os.path.normpath(str(resolved_path)))
    expected_target: dict[str, int | str] | None = None
    if allowed_targets is not None:
        normalized_source_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        expected_target = next(
            (
                target
                for source_path, target in allowed_targets.items()
                if os.path.normcase(os.path.normpath(os.path.abspath(source_path))) == normalized_source_path
            ),
            None,
        )
        if expected_target is None:
            return {"path": path, "reason": "shard_path_outside_validated_family"}
        expected_path = expected_target.get("resolved_path")
        if not isinstance(expected_path, str) or normalized_resolved_path != os.path.normcase(
            os.path.normpath(expected_path)
        ):
            return {
                "path": path,
                "resolved_path": str(resolved_path),
                "reason": "shard_target_changed",
            }
    elif normalized_resolved_path not in allowed_path_set:
        return {
            "path": path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_outside_validated_family",
        }
    if not stat.S_ISREG(resolved_stat.st_mode):
        return {
            "path": path,
            "resolved_path": str(resolved_path),
            "reason": "shard_target_not_regular_file",
        }
    if expected_target is not None:
        expected_device = expected_target.get("device")
        expected_inode = expected_target.get("inode")
        if (
            isinstance(expected_device, int)
            and isinstance(expected_inode, int)
            and expected_inode
            and (resolved_stat.st_dev, resolved_stat.st_ino) != (expected_device, expected_inode)
        ):
            return {
                "path": path,
                "resolved_path": str(resolved_path),
                "reason": "shard_target_identity_changed",
            }
        for key, current_value in (
            ("size", resolved_stat.st_size),
            ("mtime_ns", resolved_stat.st_mtime_ns),
            ("ctime_ns", resolved_stat.st_ctime_ns),
        ):
            expected_value = expected_target.get(key)
            if isinstance(expected_value, int) and current_value != expected_value:
                return {
                    "path": path,
                    "resolved_path": str(resolved_path),
                    "reason": "shard_target_content_changed",
                }
    return None


def _allowed_hf_shard_alias_paths(base_dir: Path, hf_cache_root: Path) -> list[str]:
    """Return snapshot shards resolving inside the scan root or its trusted blobs directory."""
    allowed_paths: list[str] = []
    blobs_root = _trusted_hf_blobs_root(hf_cache_root)
    for candidate_path in base_dir.rglob("*"):
        if ShardedModelDetector.match_shard_filename(candidate_path.name) is None:
            continue
        with suppress(OSError, RuntimeError):
            resolved_candidate = candidate_path.resolve(strict=True)
            resolved_candidate_path = str(resolved_candidate)
            if resolved_candidate.is_file() and (
                is_within_directory(str(base_dir), resolved_candidate_path)
                or (blobs_root is not None and is_within_directory(str(blobs_root), resolved_candidate_path))
            ):
                allowed_paths.append(resolved_candidate_path)
    return allowed_paths


def _add_path_traversal_issue_once(
    results: ModelAuditResultModel,
    *,
    location: str,
    resolved_path: str,
    reported_targets: set[str] | None = None,
) -> None:
    """Report one traversal issue per resolved target during directory discovery."""
    normalized_target = os.path.normcase(os.path.normpath(resolved_path))
    if reported_targets is not None:
        if normalized_target in reported_targets:
            return
        reported_targets.add(normalized_target)
    _add_issue_to_model(
        results,
        "Path traversal outside scanned directory",
        severity=IssueSeverity.CRITICAL.value,
        location=location,
        details={"resolved_path": resolved_path},
    )


def _resolve_discovered_shard_path(shard_path: str, results: ModelAuditResultModel) -> str | None:
    """Resolve a detected shard without aborting if it changes during discovery."""
    try:
        return str(Path(shard_path).resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as e:
        _add_issue_to_model(
            results,
            "Shard path changed during directory discovery",
            severity=IssueSeverity.INFO.value,
            location=shard_path,
            details={
                "error": str(e),
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "shard_path_changed",
            },
        )
        return None


def _is_validated_bound_source_path(path: str, config: dict[str, Any] | None) -> bool:
    """Return whether a cache binding names this private descriptor-backed source path."""
    if config is None:
        return False
    binding = config.get(_BOUND_CACHE_IDENTITY_CONFIG_KEY)
    return bool(
        isinstance(binding, CacheIdentityBinding)
        and os.path.normcase(os.path.abspath(binding.scan_path)) == os.path.normcase(os.path.abspath(path))
        and _is_private_descriptor_bound_regular_file(path)
    )


def _select_non_hdf5_preferred_scanner_id(
    path: str,
    header_format: str,
    ext: str,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Select the trusted route that owns content before an HDF5 user block."""
    follow_validated_symlink = _is_validated_bound_source_path(path, config)
    if header_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT:
        return "zip"

    if header_format == "zip":
        if config is not None and not allows_zip_structure_analysis(policy_from_config(config), path):
            return "joblib" if ext == ".joblib" else "zip"
        if is_torchserve_mar_archive(path, config):
            return "torchserve_mar"
        if is_keras_zip_archive(path, allow_config_only=ext == ".keras", config=config):
            return "keras_zip"
        if is_pytorch_zip_archive(path, config):
            return "pytorch_zip"
        if is_executorch_archive(path, config):
            return "executorch"
        if is_skops_archive(path, config):
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

    if ext == ".nemo":
        if header_format == "tar":
            return "nemo"
        if header_format == "gzip" and (
            _gzip_tar_trailing_status_for_config(path, config) is not None
            or validate_file_type_with_formats(path, header_format, "nemo")
        ):
            return "nemo"

    scanner_policy = policy_from_config(config) if config is not None else None
    tokenizer_template_route = (
        config is not None
        and header_format in {"unknown", "pytorch_binary", "jax_checkpoint"}
        and huggingface_tokenizer_json_has_template_route_evidence(path)
    )
    if tokenizer_template_route and scanner_policy is not None and scanner_policy.allows("jinja2_template"):
        return "jinja2_template"

    tokenizer_jax_route = (
        config is not None
        and ext == ".json"
        and header_format == "unknown"
        and huggingface_tokenizer_json_has_jax_route_evidence(path)
    )
    selected_ambiguous_jax_json_route = (
        scanner_policy is not None
        and scanner_policy.active
        and scanner_policy.allows("jax_checkpoint")
        and ext == ".json"
        and header_format == "unknown"
        and not is_huggingface_tokenizer_json_file(path)
        and (not tokenizer_template_route or not scanner_policy.allows("jinja2_template"))
        and is_jax_json_checkpoint_file(
            path,
            follow_validated_symlink=follow_validated_symlink,
        )
    )
    if (
        config is not None
        and ext == ".json"
        and header_format == "unknown"
        and scanner_policy is not None
        and scanner_policy.allows("jax_checkpoint")
        and not is_huggingface_tokenizer_json_file(path)
        and (not tokenizer_template_route or not scanner_policy.allows("jinja2_template"))
        and (
            is_confirmed_jax_json_checkpoint_file(
                path,
                follow_validated_symlink=follow_validated_symlink,
            )
            or tokenizer_jax_route
            or selected_ambiguous_jax_json_route
        )
    ):
        return "jax_checkpoint"

    if scanner_policy is not None and scanner_policy.allows("jax_checkpoint") and not ext:
        from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner

        if JaxCheckpointScanner.can_handle(path):
            return "jax_checkpoint"

    return _registry.get_scanner_id_for_header_format(header_format)


def _gzip_tar_trailing_status_for_config(path: str, config: dict[str, Any] | None) -> str | None:
    """Return invalid/nonzero gzip TAR tail status using configured compressed-wrapper limits."""
    return gzip_tar_trailing_data_status(
        path,
        max_decompressed_bytes=config.get("compressed_max_decompressed_bytes") if config is not None else None,
        max_decompression_ratio=config.get("compressed_max_decompression_ratio") if config is not None else None,
    )


def _select_hdf5_userblock_supplemental_scanner_id(
    path: str,
    header_format: str,
    ext: str,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Preserve the non-HDF5 scanner that owns a user-block prefix or path."""
    if header_format in {"zip", EXECUTABLE_ZIP_POLYGLOT_FORMAT}:
        # The HDF5 user-block dispatcher validates and scans each complete ZIP
        # segment independently; probing the concatenated prefix here would
        # reject valid earlier segments as undeclared local records.
        return "zip"
    scanner_id = _select_non_hdf5_preferred_scanner_id(path, header_format, ext, config)
    if scanner_id is not None:
        return scanner_id

    path_scanner_id = _registry.get_scanner_id_for_content_routed_filename(path)
    return path_scanner_id if path_scanner_id != "keras_h5" else None


def _select_preferred_scanner_id(
    path: str,
    header_format: str,
    ext: str,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Select a scanner by trusted file structure, not just suffix."""
    if find_hdf5_signature_offset(path) is not None:
        return "keras_h5"
    return _select_non_hdf5_preferred_scanner_id(path, header_format, ext, config)


def _merge_supplemental_scanner_analysis(
    path: str,
    result: ScanResult,
    config: dict[str, Any],
    scanner_selection: ScannerSelectionPolicy,
    supplemental_scanner_id: str | None,
    *,
    context: str,
) -> None:
    """Merge findings from a trusted overlapping content route."""
    if supplemental_scanner_id is None:
        return
    if not scanner_selection.allows(supplemental_scanner_id):
        add_scanner_selection_skip_check(
            result,
            path,
            supplemental_scanner_id,
            scanner_selection,
            context=context,
        )
        return

    scanner_class = _registry.load_scanner_by_id(supplemental_scanner_id)
    if scanner_class is None:
        supplemental_result = _make_unavailable_recognized_format_result(
            path,
            supplemental_scanner_id,
            supplemental_scanner_id,
        )
    else:
        supplemental_result = scanner_class(config=config).scan(path)

    primary_bytes_scanned = result.bytes_scanned
    result.merge(supplemental_result)
    result.bytes_scanned = max(primary_bytes_scanned, supplemental_result.bytes_scanned)
    result.metadata.setdefault("supplemental_scanners", []).append(supplemental_scanner_id)


def _merge_pytorch_binary_supplemental_analysis(
    path: str,
    result: ScanResult,
    config: dict[str, Any],
    scanner_selection: ScannerSelectionPolicy,
    supplemental_scanner_id: str | None,
) -> None:
    """Merge strict format-specific findings without dropping raw `.bin` checks."""
    supplemental_config = dict(config)
    if supplemental_scanner_id == "executorch":
        from .scanners.executorch_scanner import PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY

        supplemental_config[PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY] = True
    _merge_supplemental_scanner_analysis(
        path,
        result,
        supplemental_config,
        scanner_selection,
        supplemental_scanner_id,
        context="supplemental .bin content analysis",
    )


def _merge_jax_metadata_supplemental_analysis(
    path: str,
    result: ScanResult,
    config: dict[str, Any],
    scanner_selection: ScannerSelectionPolicy,
) -> None:
    """Preserve JAX/Orbax metadata findings when a generic manifest scanner owns the file."""
    if result.scanner_name == "jax_checkpoint":
        return
    current_file = normalize_repository_member_path(config.get(REPOSITORY_CURRENT_FILE_CONFIG_KEY))
    inventory = repository_file_inventory_context_from_config(config)
    verified_orbax_sibling = config.get(JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY) is True
    if current_file is not None and current_file.rsplit("/", 1)[-1].lower() == "metadata.json":
        parent = current_file.rpartition("/")[0]
        prefix = f"{parent}/" if parent else ""
        verified_orbax_sibling = any(
            f"{prefix}{marker_name}" in inventory.files
            for marker_name in ("_CHECKPOINT", "orbax_checkpoint_metadata.json")
        )
    if _registry.get_scanner_id_for_content_routed_filename(path) != "jax_checkpoint" and not verified_orbax_sibling:
        return
    supplemental_config = dict(config)
    if verified_orbax_sibling:
        supplemental_config[JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY] = True
    _merge_supplemental_scanner_analysis(
        path,
        result,
        supplemental_config,
        scanner_selection,
        "jax_checkpoint",
        context="supplemental JAX metadata analysis",
    )


def _is_direct_header_route(scanner_id: str, header_format: str) -> bool:
    """Return whether the detected header directly maps to this scanner."""
    return header_format != "unknown" and HEADER_FORMAT_TO_SCANNER_ID.get(header_format) == scanner_id


def _preferred_scanner_can_handle(
    scanner_class: type[BaseScanner],
    scanner_id: str,
    header_format: str,
    path: str,
    config: dict[str, Any] | None = None,
) -> bool:
    """Honor trusted header routing even when scanner can_handle is suffix-gated."""
    if (
        scanner_id == "jax_checkpoint"
        and config is not None
        and config.get(JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY) is True
    ):
        return True
    if (
        scanner_id == "jax_checkpoint"
        and _is_validated_bound_source_path(path, config)
        and is_jax_json_checkpoint_file(path, follow_validated_symlink=True)
    ):
        return True

    if scanner_id == "keras_h5" and find_hdf5_signature_offset(path) is not None:
        logger.debug(
            "Using %s scanner for validated HDF5 file %s",
            scanner_class.name,
            path,
        )
        return True

    if header_format == "zip" and scanner_id in {
        "executorch",
        "keras_zip",
        "pytorch_zip",
        "skops",
        "torchserve_mar",
    }:
        return True

    if scanner_id == "nemo" and header_format == "gzip" and _gzip_tar_trailing_status_for_config(path, config):
        return True

    if scanner_class.can_handle(path):
        return True

    scanner_policy = policy_from_config(config)
    if (
        scanner_id == "jax_checkpoint"
        and scanner_policy.active
        and scanner_policy.allows("jax_checkpoint")
        and header_format == "unknown"
        and Path(path).suffix.lower() == ".json"
        and not is_huggingface_tokenizer_json_file(path)
        and is_jax_json_checkpoint_file(
            path,
            follow_validated_symlink=_is_validated_bound_source_path(path, config),
        )
    ):
        logger.debug(
            "Using %s scanner for selected ambiguous JAX JSON candidate %s",
            scanner_class.name,
            path,
        )
        return True

    if scanner_id == "zip":
        return False

    if os.path.exists(path) and _is_direct_header_route(scanner_id, header_format):
        logger.debug(
            "Using %s scanner for %s based on detected %s header despite can_handle rejection",
            scanner_class.name,
            path,
            header_format,
        )
        return True

    return False


def _has_only_allowed_alternate_format_inconclusive_reasons(result: ScanResult, validated_format: str) -> bool:
    allowed_reasons = _ALTERNATE_VALIDATED_FORMAT_ALLOWED_INCONCLUSIVE_REASONS.get(validated_format, frozenset())
    reasons = result.metadata.get(SCAN_OUTCOME_REASONS_METADATA_KEY)
    if not isinstance(reasons, list):
        return bool(result.success)
    return bool(reasons) and all(isinstance(reason, str) and reason in allowed_reasons for reason in reasons)


def _has_private_actionable_scanner_evidence(result: ScanResult) -> bool:
    for metadata_key in (ACTIONABLE_FAILED_CHECKS_METADATA_KEY, SUPPRESSED_FAILED_CHECKS_METADATA_KEY):
        private_checks = result._private_metadata.get(metadata_key)
        if _private_checks_contain_actionable_evidence(private_checks):
            return True
    return False


def _private_checks_contain_actionable_evidence(private_checks: Any) -> bool:
    if not isinstance(private_checks, list):
        return False
    for private_check in private_checks:
        if not isinstance(private_check, dict):
            continue
        if private_check.get("severity") in {IssueSeverity.WARNING.value, IssueSeverity.CRITICAL.value}:
            return True
    return False


def _validated_alternate_format_for_mismatch(
    result: ScanResult,
    *,
    header_format: str,
    magic_format: str,
) -> str | None:
    """Return a validated alternate format that can demote extension mismatch."""
    validated_format = result.metadata.get(VALIDATED_FORMAT_METADATA_KEY)
    if not isinstance(validated_format, str):
        return None
    if validated_format != result.scanner_name:
        return None
    if validated_format not in _ALTERNATE_VALIDATED_FORMAT_ALLOWED_INCONCLUSIVE_REASONS:
        return None
    if header_format not in {validated_format, PROTOBUF_MODEL_CANDIDATE_FORMAT} and magic_format not in {
        validated_format,
        PROTOBUF_MODEL_CANDIDATE_FORMAT,
    }:
        return None
    if result.has_errors or result.has_warnings or _has_private_actionable_scanner_evidence(result):
        return None
    if result.metadata.get(OPERATIONAL_ERROR_METADATA_KEY) is True:
        return None
    if (
        result.success is False
        or result.metadata.get(SCAN_OUTCOME_METADATA_KEY) == INCONCLUSIVE_SCAN_OUTCOME
        or result.metadata.get("analysis_incomplete") is True
    ) and not _has_only_allowed_alternate_format_inconclusive_reasons(result, validated_format):
        return None
    return validated_format


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


def _make_incomplete_format_detection_read_result(path: str, error: OSError) -> ScanResult:
    """Fail closed when no owning scanner can classify a file after a read failure."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Format Detection",
        passed=False,
        message=f"File format could not be determined because the file could not be read: {error}",
        severity=IssueSeverity.INFO,
        location=path,
        details={"path": path, "error": str(error), "analysis_incomplete": True},
    )
    _mark_inconclusive_scan_outcome(result, _FORMAT_DETECTION_READ_FAILED_REASON)
    _mark_operational_scan_error(result, _FORMAT_DETECTION_READ_FAILED_REASON)
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


def _make_incomplete_protobuf_model_result(path: str) -> ScanResult:
    """Fail closed when a protobuf candidate cannot receive tentative analysis."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Protobuf Model Routing",
        passed=False,
        message=(
            "Protobuf model routing was inconclusive because tentative protobuf "
            "analysis was unavailable for a bounded-probe candidate"
        ),
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": PROTOBUF_MODEL_CANDIDATE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_sentencepiece_model_proto_result(path: str) -> ScanResult:
    """Fail closed when a SentencePiece-like protobuf fails ownership validation."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="SentencePiece ModelProto Routing",
        passed=False,
        message=(
            "SentencePiece ModelProto routing was inconclusive because the payload "
            "looked like a tokenizer protobuf but failed ownership validation"
        ),
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _SENTENCEPIECE_MODEL_PROTO_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _SENTENCEPIECE_MODEL_PROTO_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_llamafile_routing_result(path: str, config: dict[str, Any]) -> ScanResult:
    """Fail closed when an executable Llamafile marker probe cannot complete."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Llamafile Routing",
        passed=False,
        message="Llamafile routing was inconclusive because bounded marker bytes could not be read",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _LLAMAFILE_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _LLAMAFILE_ROUTING_INCOMPLETE_REASON)

    merge_executable_zip_container_findings(
        path,
        result,
        config,
        context="inconclusive executable ZIP polyglot",
    )
    result.finish(success=False)
    return result


def _make_incomplete_nemo_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded NeMo structural routing cannot reach a decision."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="NeMo Routing",
        passed=False,
        message="NeMo routing was inconclusive because the bounded TAR member probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": NEMO_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, "nemo_routing_incomplete")
    _mark_operational_scan_error(result, "nemo_routing_incomplete")
    result.finish(success=False)
    return result


def _make_incomplete_mxnet_symbol_routing_result(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Fail closed when bounded MXNet symbol routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="MXNet Symbol Routing",
        passed=False,
        message="MXNet symbol routing was inconclusive because the bounded JSON probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON)

    from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner
    from modelaudit.scanners.jinja2_template_scanner import Jinja2TemplateScanner
    from modelaudit.scanners.manifest_scanner import ManifestScanner
    from modelaudit.scanners.mxnet_scanner import MXNetScanner

    scanner_selection = policy_from_config(config)

    def merge_owner_result(owner_result: ScanResult) -> None:
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        owner_reasons = list(owner_result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        result.metadata["scan_outcome_reasons"] = list(dict.fromkeys([*owner_reasons, *existing_reasons]))

    if Path(path).suffix.lower() == ".params":
        if scanner_selection.allows("mxnet"):
            MXNetScanner(config=config).scan_params_file_security(path, result)
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "mxnet",
                scanner_selection,
                context="inconclusive MXNet params byte analysis",
            )

    if os.path.getsize(
        path
    ) <= JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES or JaxCheckpointScanner.should_analyze_inconclusive_json_overlap(
        path
    ):
        if scanner_selection.allows("jax_checkpoint"):
            merge_owner_result(JaxCheckpointScanner(config=config).scan(path))
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "jax_checkpoint",
                scanner_selection,
                context="overlapping JAX JSON analysis",
            )

    manifest_covered_templates = False
    if ManifestScanner.can_handle(path):
        if scanner_selection.allows("manifest"):
            manifest_result = ManifestScanner(config=config).scan(path)
            merge_owner_result(manifest_result)
            manifest_covered_templates = manifest_result.metadata.get("analysis_incomplete") is not True
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "manifest",
                scanner_selection,
                context="overlapping manifest JSON analysis",
            )
    if not manifest_covered_templates and Jinja2TemplateScanner.can_handle(path):
        if scanner_selection.allows("jinja2_template"):
            merge_owner_result(Jinja2TemplateScanner(config=config).scan(path))
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "jinja2_template",
                scanner_selection,
                context="overlapping Jinja JSON analysis",
            )
    result.finish(success=False)
    return result


def _make_incomplete_xgboost_ubjson_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded extensionless UBJSON routing cannot confirm XGBoost."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="XGBoost UBJSON Routing",
        passed=False,
        message="Extensionless UBJSON routing was inconclusive because the bounded learner probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _XGBOOST_UBJSON_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _XGBOOST_UBJSON_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_tensorflow_protobuf_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded TensorFlow protobuf routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="TensorFlow Protobuf Routing",
        passed=False,
        message="TensorFlow protobuf routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_onnx_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded ONNX protobuf routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="ONNX Routing",
        passed=False,
        message="ONNX routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": ONNX_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _ONNX_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _ONNX_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_pickle_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded protocol-less Pickle routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Pickle Routing",
        passed=False,
        message="Pickle routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": PICKLE_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    _mark_inconclusive_scan_outcome(result, _PICKLE_ROUTING_INCOMPLETE_REASON)
    _mark_operational_scan_error(result, _PICKLE_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _scan_executable_zip_polyglot(path: str, config: dict[str, Any]) -> ScanResult:
    """Preserve container and subtype analysis for executable-prefixed ZIPs."""
    result = ScanResult(scanner_name="zip")
    merge_executable_zip_container_findings(
        path,
        result,
        config,
        context="executable ZIP polyglot",
    )
    result.finish(success=not result.has_errors)
    return result


def _calculate_file_hash(
    file_path: str,
    *,
    deadline: float | None = None,
    follow_validated_symlink: bool = False,
) -> str:
    """Calculate SHA256 hash of a file for deduplication purposes.

    Raises:
        Exception: If file cannot be hashed (security: prevents hash collision attacks)
    """
    identity_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    path_stat_before = os.stat(file_path, follow_symlinks=follow_validated_symlink)
    if not stat.S_ISREG(path_stat_before.st_mode):
        raise OSError(f"Refusing to hash non-regular file: {file_path}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | (0 if follow_validated_symlink else getattr(os, "O_NOFOLLOW", 0))
    )
    descriptor = os.open(file_path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            opened_stat = os.fstat(source.fileno())
            if any(getattr(path_stat_before, field) != getattr(opened_stat, field) for field in identity_fields):
                raise OSError(f"File changed before hashing: {file_path}")

            hash_sha256 = hashlib.sha256()
            while True:
                if deadline is not None and time.time() > deadline:
                    raise TimeoutError(f"File hashing timed out: {file_path}")
                chunk = source.read(8192)
                if not chunk:
                    break
                hash_sha256.update(chunk)

            final_stat = os.fstat(source.fileno())
            path_stat_after = os.stat(file_path, follow_symlinks=follow_validated_symlink)
            if any(
                getattr(opened_stat, field) != getattr(candidate, field)
                for candidate in (final_stat, path_stat_after)
                for field in identity_fields
            ):
                raise OSError(f"File changed while hashing: {file_path}")
            return hash_sha256.hexdigest()
    finally:
        os.close(descriptor)


def _should_defer_hash_for_safetensors_header_limit(file_path: str, config: dict[str, Any]) -> bool:
    """Avoid full-file hashing for terminal bounded outcomes from oversized SafeTensors framing."""
    try:
        max_header_bytes = int(config.get("max_safetensors_header_bytes", SAFETENSORS_MAX_HEADER_BYTES))
    except (TypeError, ValueError):
        return False
    return should_defer_safetensors_header_limit_hash(file_path, max_header_bytes)


def _should_defer_hash_for_file_backed_hdf5(file_path: str) -> bool:
    """Avoid pre-dispatch whole-file hashing for HDF5 scans handled through h5py metadata traversal."""
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        return False

    return file_size > DEFAULT_MAX_FILE_READ_SIZE and find_hdf5_signature_offset(file_path) is not None


def _should_defer_hash_for_max_file_size(
    file_path: str,
    config: dict[str, Any],
    *,
    file_size: int | None = None,
) -> bool:
    """Avoid hashing files that regular scanning will reject on max_file_size."""
    try:
        max_file_size = int(config.get("max_file_size", 0) or 0)
    except (TypeError, ValueError):
        return False
    if max_file_size <= 0:
        return False

    if file_size is None:
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            return False

    return file_size > max_file_size and not should_use_advanced_handler(file_path)


def _should_defer_hash_for_max_total_size(
    config: dict[str, Any],
    *,
    hashed_bytes: int = 0,
) -> bool:
    """Avoid hashing files after the aggregate scan read budget is crossed."""
    try:
        max_total_size = int(config.get("max_total_size", 0) or 0)
    except (TypeError, ValueError):
        return False
    if max_total_size <= 0:
        return False

    return hashed_bytes > max_total_size


_FILE_BACKED_HDF5_UNHASHABLE_PREFIX = "unhashable_file_backed_hdf5_"
_FILE_BACKED_ONNX_UNHASHABLE_PREFIX = "unhashable_file_backed_onnx_"


def _is_file_backed_hdf5_hash_placeholder(content_hash: str) -> bool:
    return content_hash.startswith(_FILE_BACKED_HDF5_UNHASHABLE_PREFIX)


def _directory_owner_hash_is_unverifiable(
    content_hash: str,
    *,
    allow_file_backed_hdf5: bool,
) -> bool:
    if not content_hash.startswith("unhashable_"):
        return False
    return not (allow_file_backed_hdf5 and _is_file_backed_hdf5_hash_placeholder(content_hash))


def _directory_owner_hash_changed(
    before_hash: str | None,
    after_hash: str | None,
    *,
    allow_file_backed_hdf5: bool,
) -> bool:
    if before_hash == after_hash:
        return False
    return not (
        allow_file_backed_hdf5
        and isinstance(before_hash, str)
        and isinstance(after_hash, str)
        and _is_file_backed_hdf5_hash_placeholder(before_hash)
        and _is_file_backed_hdf5_hash_placeholder(after_hash)
    )


def _is_incomplete_aggregate_hash_placeholder(content_hash: str) -> bool:
    return content_hash.startswith(
        (
            _FILE_BACKED_HDF5_UNHASHABLE_PREFIX,
            _FILE_BACKED_ONNX_UNHASHABLE_PREFIX,
            "unhashable_max_file_size_",
            "unhashable_max_total_size_",
            "unhashable_timeout_",
            "unhashable_legacy_pytorch_read_limit_",
            "unhashable_pytorch_zip_read_limit_",
        )
    )


def _hash_files_by_path(
    file_paths: list[str],
    *,
    config: dict[str, Any] | None = None,
    routing_paths: dict[str, str] | None = None,
    follow_symlink_paths: Collection[str] = (),
    hashed_identities: dict[str, dict[str, int]] | None = None,
    deadline: float | None = None,
) -> dict[str, str]:
    """Hash files individually so scan results stay path-specific.

    Args:
        file_paths: List of file paths to group
        config: Scan settings used for bounded format-specific hashing decisions.
        routing_paths: Original model paths used for extension-sensitive read limits.

    Returns:
        Dictionary mapping each file path to its content hash. Files that fail to
        hash get unique placeholder values so they still scan independently.
    """
    content_hashes: dict[str, str] = {}
    hashes_by_inode: dict[tuple[int, int, int, int, int], str] = {}
    followed_paths = set(follow_symlink_paths)
    hashed_bytes = 0
    hash_budget_exhausted = False

    for file_path in file_paths:
        if hash_budget_exhausted:
            content_hashes[file_path] = f"unhashable_max_total_size_{id(file_path)}"
            continue
        if deadline is not None and time.time() > deadline:
            content_hashes[file_path] = f"unhashable_timeout_{id(file_path)}"
            continue
        hash_config = config or {}
        routing_path = routing_paths.get(file_path, file_path) if routing_paths is not None else file_path
        if _should_defer_hash_for_safetensors_header_limit(routing_path, hash_config):
            content_hashes[file_path] = f"unhashable_bounded_safetensors_{id(file_path)}"
            continue
        if _should_defer_hash_for_file_backed_hdf5(routing_path):
            content_hashes[file_path] = f"unhashable_file_backed_hdf5_{id(file_path)}"
            continue
        if should_defer_hash_for_file_backed_onnx(routing_path, hash_config):
            content_hashes[file_path] = f"{_FILE_BACKED_ONNX_UNHASHABLE_PREFIX}{id(file_path)}"
            with suppress(OSError):
                hashed_bytes += os.path.getsize(file_path)
            continue
        if should_defer_hash_for_pytorch_read_limit(routing_path, hash_config):
            content_hashes[file_path] = f"unhashable_pytorch_zip_read_limit_{id(file_path)}"
            continue
        if _should_defer_hash_for_max_file_size(routing_path, hash_config):
            content_hashes[file_path] = f"unhashable_max_file_size_{id(file_path)}"
            continue
        try:
            follow_validated_symlink = file_path in followed_paths
            inode_key: tuple[int, int, int, int, int] | None = None
            pre_hash_stat: os.stat_result | None = None
            try:
                pre_hash_stat = os.stat(file_path, follow_symlinks=follow_validated_symlink)
                if pre_hash_stat.st_nlink > 1:
                    inode_key = (
                        pre_hash_stat.st_dev,
                        pre_hash_stat.st_ino,
                        pre_hash_stat.st_size,
                        pre_hash_stat.st_mtime_ns,
                        pre_hash_stat.st_ctime_ns,
                    )
                    if cached_hash := hashes_by_inode.get(inode_key):
                        content_hashes[file_path] = cached_hash
                        if hashed_identities is not None:
                            hashed_identities[file_path] = {
                                "device": pre_hash_stat.st_dev,
                                "inode": pre_hash_stat.st_ino,
                                "size": pre_hash_stat.st_size,
                                "mtime_ns": pre_hash_stat.st_mtime_ns,
                                "ctime_ns": pre_hash_stat.st_ctime_ns,
                            }
                        continue
            except OSError:
                # Fall back to direct hashing when stat is unavailable or the file changes mid-scan.
                pass

            current_file_size = os.path.getsize(file_path)
            if _should_defer_hash_for_max_total_size(
                hash_config,
                hashed_bytes=hashed_bytes + current_file_size,
            ):
                content_hashes[file_path] = f"unhashable_max_total_size_{id(file_path)}"
                hash_budget_exhausted = True
                continue
            hashed_bytes += current_file_size
            if follow_validated_symlink:
                content_hashes[file_path] = _calculate_file_hash(
                    file_path,
                    deadline=deadline,
                    follow_validated_symlink=True,
                )
            else:
                content_hashes[file_path] = _calculate_file_hash(file_path, deadline=deadline)
            post_hash_stat = os.stat(file_path, follow_symlinks=follow_validated_symlink)
            if pre_hash_stat is None or any(
                getattr(pre_hash_stat, field) != getattr(post_hash_stat, field)
                for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
            ):
                raise OSError(f"File changed while hashing: {file_path}")
            if hashed_identities is not None:
                hashed_identities[file_path] = {
                    "device": post_hash_stat.st_dev,
                    "inode": post_hash_stat.st_ino,
                    "size": post_hash_stat.st_size,
                    "mtime_ns": post_hash_stat.st_mtime_ns,
                    "ctime_ns": post_hash_stat.st_ctime_ns,
                }
            if inode_key is not None:
                hashes_by_inode[inode_key] = content_hashes[file_path]
        except Exception as e:
            # Log error but continue with other files to prevent single I/O failure from aborting entire scan
            logger.warning(f"Failed to hash file {file_path}: {e}. Skipping deduplication for this file.")
            content_hashes[file_path] = f"unhashable_{id(file_path)}"

    return content_hashes


@contextmanager
def _staged_directory_owner_scan_path(
    root_path: Path,
    owner_snapshot: tuple[_DirectoryOwnerSnapshotEntry, ...],
    owner_hashes: dict[str, str],
    *,
    config: dict[str, Any],
    deadline: float,
    source_paths_by_owner_path: dict[str, str] | None = None,
) -> Iterator[str]:
    """Yield a copied owner snapshot when descriptor-backed paths are unavailable."""
    temporary_directory = tempfile.mkdtemp(prefix="modelaudit-directory-owner-")
    try:
        staged_root = Path(temporary_directory) / (root_path.name or "owner-root")
        staged_root.mkdir()
        for owner_entry in owner_snapshot:
            if owner_entry.entry_type == "directory" and owner_entry.relative_parts:
                staged_root.joinpath(*owner_entry.relative_parts).mkdir(parents=True, exist_ok=True)

        staged_source_by_original: dict[str, str] = {}
        for source_path in owner_hashes:
            content_source_path = (source_paths_by_owner_path or {}).get(source_path, source_path)
            relative_parts = Path(os.path.relpath(source_path, root_path)).parts
            staged_source = staged_root.joinpath(*relative_parts)
            staged_source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(content_source_path, staged_source, follow_symlinks=False)
            staged_source_by_original[source_path] = str(staged_source)

        staged_hashes = _hash_files_by_path(
            list(staged_source_by_original.values()),
            config=config,
            routing_paths={staged_source: staged_source for staged_source in staged_source_by_original.values()},
            deadline=deadline,
        )
        if any(
            staged_hashes.get(staged_source) != owner_hashes[source_path]
            for source_path, staged_source in staged_source_by_original.items()
        ):
            raise OSError("Directory owner staged snapshot did not match pre-dispatch hashes")

        yield str(staged_root)
    finally:
        with suppress(Exception):
            shutil.rmtree(temporary_directory)


@contextmanager
def _directory_owner_scan_path(
    root_path: Path,
    owner_snapshot: tuple[_DirectoryOwnerSnapshotEntry, ...],
    owner_hashes: dict[str, str],
    *,
    config: dict[str, Any],
    deadline: float,
    force_staged: bool = False,
    require_bound: bool = False,
    source_paths_by_owner_path: dict[str, str] | None = None,
    trusted_root_symlink: bool = False,
) -> Iterator[str]:
    """Yield a bound or hash-verified copied path for logical directory-owner scanning."""
    with ExitStack() as scan_path_stack:
        if not force_staged:
            try:
                owner_scan_path = scan_path_stack.enter_context(
                    _bound_directory_owner_scan_path(
                        root_path,
                        trusted_root_symlink=trusted_root_symlink,
                    )
                )
            except OSError:
                if require_bound:
                    raise
                owner_scan_path = scan_path_stack.enter_context(
                    _staged_directory_owner_scan_path(
                        root_path,
                        owner_snapshot,
                        owner_hashes,
                        config=config,
                        deadline=deadline,
                        source_paths_by_owner_path=source_paths_by_owner_path,
                    ),
                )
        else:
            if require_bound:
                raise OSError("Descriptor-backed directory owner path required for deferred source hashes")
            owner_scan_path = scan_path_stack.enter_context(
                _staged_directory_owner_scan_path(
                    root_path,
                    owner_snapshot,
                    owner_hashes,
                    config=config,
                    deadline=deadline,
                    source_paths_by_owner_path=source_paths_by_owner_path,
                ),
            )
        yield owner_scan_path


def _is_directory_link(path: Path) -> bool:
    """Return whether a directory entry is a symlink, junction, or other Windows reparse point."""
    if path.is_symlink():
        return True

    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        with suppress(OSError):
            if is_junction():
                return True

    with suppress(OSError):
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        file_attributes = getattr(path.lstat(), "st_file_attributes", 0) or 0
        return bool(reparse_flag and file_attributes & reparse_flag)
    return False


def _stat_is_windows_reparse_point(stat_result: os.stat_result) -> bool:
    """Return whether a stat result reports a Windows reparse-point entry."""
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    file_attributes = getattr(stat_result, "st_file_attributes", 0) or 0
    return bool(reparse_flag and file_attributes & reparse_flag)


def _resolve_directory_scan_target(
    file_path: Path,
    base_dir: Path,
    *,
    is_hf_cache: bool,
    hf_cache_root: Path | None,
    results: ModelAuditResultModel,
    reported_traversal_targets: set[str] | None = None,
    preserve_bound_path: bool = False,
    hf_snapshot_path: Path | None = None,
) -> tuple[Path | None, bool, bool]:
    """Resolve a directory entry and reject symlink traversal outside the scan root."""
    is_symlink = file_path.is_symlink()
    try:
        entry_stat = file_path.lstat()
        if not is_symlink and _stat_is_windows_reparse_point(entry_stat):
            raise OSError("Windows reparse point cannot be safely scanned")
        # Strict resolution of valid relative file symlinks is unreliable on
        # some Windows versions. Resolve once and verify that target directly.
        resolved_file = file_path.resolve()
        if is_symlink and resolved_file == file_path.absolute():
            try:
                raw_target = Path(os.readlink(file_path))
            except OSError as e:
                if not file_path.exists():
                    raise FileNotFoundError("Symlink target does not exist") from e
                raise
            if not raw_target.is_absolute():
                raw_target = file_path.parent / raw_target
            resolved_file = raw_target.resolve()
        resolved_file.stat()
    except (OSError, RuntimeError) as e:
        if is_symlink and isinstance(e, FileNotFoundError):
            _add_issue_to_model(
                results,
                "Broken symlink encountered",
                severity=IssueSeverity.INFO.value,
                location=str(file_path),
                details={
                    "error": str(e),
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "directory_entry_unavailable",
                },
            )
            return None, False, True
        _add_issue_to_model(
            results,
            "Directory entry unavailable during discovery",
            severity=IssueSeverity.INFO.value,
            location=str(file_path),
            details={
                "error": str(e),
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "directory_entry_unavailable",
            },
        )
        return None, False, True

    # Check if this is a HuggingFace cache symlink scenario
    is_hf_cache_symlink = False
    if is_symlink and is_hf_cache and _is_hf_cache_snapshot_alias(hf_snapshot_path or file_path, hf_cache_root):
        # Reuse the canonical target resolved above. On Windows, os.readlink()
        # may expose a device-path spelling that cannot safely be rejoined.
        resolved_target = resolved_file
        # Check if target is in the blobs directory of the same model cache
        if hf_cache_root is not None:
            blobs_root = _trusted_hf_blobs_root(hf_cache_root)
            if blobs_root is not None and is_within_directory(str(blobs_root), str(resolved_target)):
                is_hf_cache_symlink = True
                # Update the resolved_file to the actual target for scanning
                resolved_file = resolved_target

    containment_base_dir = base_dir.resolve() if preserve_bound_path else base_dir
    if not is_hf_cache_symlink and not is_within_directory(str(containment_base_dir), str(resolved_file)):
        _add_path_traversal_issue_once(
            results,
            location=str(file_path),
            resolved_path=str(resolved_file),
            reported_targets=reported_traversal_targets,
        )
        return None, False, False

    preserve_scan_path = preserve_bound_path and not is_symlink
    return (file_path if preserve_scan_path else resolved_file), is_hf_cache_symlink, False


def _hf_cache_snapshot_alias_has_safe_parent_components(snapshot_path: Path, hf_cache_root: Path | None) -> bool:
    """Return whether a snapshot alias parent path avoids symlink components."""
    if hf_cache_root is None:
        return False

    absolute_path = Path(os.path.abspath(snapshot_path.expanduser()))
    resolved_cache_root = _resolve_hf_cache_path(hf_cache_root)
    cache_root_spellings = [Path(os.path.abspath(hf_cache_root.expanduser()))]
    for hub_root in _get_hf_cache_root_spellings():
        model_cache_root = hub_root / resolved_cache_root.name
        if _resolve_hf_cache_path(model_cache_root) == resolved_cache_root:
            cache_root_spellings.append(model_cache_root)

    for cache_root in dict.fromkeys(cache_root_spellings):
        try:
            relative_parts = absolute_path.relative_to(cache_root).parts
        except ValueError:
            continue
        if len(relative_parts) < 3 or relative_parts[0].lower() != "snapshots" or relative_parts[1] in {"", ".", ".."}:
            return False
        current = cache_root
        for part in relative_parts[:-1]:
            current = current / part
            if current.is_symlink():
                return False
        return True
    return False


def _should_scan_hf_cache_alias_lexically_for_onnx(snapshot_path: Path, hf_cache_root: Path | None) -> bool:
    """Return whether an HF cache alias should be scanned via its snapshot path for ONNX sidecars."""
    suffix = snapshot_path.suffix.lower()
    if suffix == ".onnx":
        return True
    if not _hf_cache_snapshot_alias_has_safe_parent_components(snapshot_path, hf_cache_root):
        return False
    try:
        return detect_file_format_for_skip_filter(str(snapshot_path)) == "onnx"
    except (OSError, RuntimeError, ValueError):
        return False


def _unclassified_symlink_names(root: str, dirs: list[str], files: list[str]) -> list[str]:
    """Return file-like symlinks omitted from ``os.walk``'s file classification."""
    classified_files = set(files)
    unclassified_symlinks: list[str] = []
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name in classified_files:
                    continue
                try:
                    is_symlink = entry.is_symlink()
                except OSError:
                    is_symlink = True
                if not is_symlink:
                    continue
                try:
                    if entry.is_dir(follow_symlinks=True):
                        continue
                except OSError as error:
                    # Preserve the file-like fallback when following the symlink cannot be classified.
                    logger.debug("Unable to classify symlink %s in %s as a directory: %s", entry.name, root, error)
                unclassified_symlinks.append(entry.name)
    except OSError:
        return []
    return sorted(unclassified_symlinks)


def validate_scan_config(config: dict[str, Any]) -> ScanConfigModel:
    """Validate configuration parameters for scanning using Pydantic model."""
    try:
        return ScanConfigModel.from_dict(config)
    except Exception as e:
        raise ValueError(f"Invalid scan configuration: {e}") from e


def _normalize_repository_inventory_config(config: dict[str, Any]) -> dict[str, Any]:
    if REPOSITORY_FILE_INVENTORY_CONFIG_KEY in config:
        config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = repository_file_inventory_context_from_config(config)
    return config


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
    local_source_report_path = str(path)
    local_source_boundary_stack = ExitStack()
    bound_local_source_path: str | None = None
    resolved_local_source_path: str | None = None
    local_source_receipt_value = kwargs.pop(_LOCAL_SOURCE_RECEIPT_CONFIG_KEY, None)
    expected_local_source_receipt = _validated_local_source_receipt(local_source_receipt_value)
    local_source_bound_guard_value = kwargs.pop(_LOCAL_SOURCE_BOUND_GUARD_CONFIG_KEY, None)
    local_source_bound_guard = (
        local_source_bound_guard_value if isinstance(local_source_bound_guard_value, _BoundLocalSourceGuard) else None
    )
    owned_local_source_guard: _BoundLocalSourceGuard | None = None
    bound_local_source_owner_root_trusted = False
    bound_local_source_is_lexical_link = False
    local_source_initial_namespace: tuple[_DirectoryOwnerSnapshotEntry, ...] | None = None
    local_source_initial_namespace_error: Exception | None = None
    dvc_parent_file = kwargs.pop(_DVC_PARENT_FILE_CONFIG_KEY, None)
    dvc_remaining_total_size = kwargs.pop(_DVC_REMAINING_TOTAL_SIZE_CONFIG_KEY, None)
    dvc_total_size_limit = kwargs.pop(_DVC_TOTAL_SIZE_LIMIT_CONFIG_KEY, None)
    dvc_excluded_paths_value = kwargs.pop(_DVC_EXCLUDED_PATHS_CONFIG_KEY, ())
    dvc_coverage_roots_value = kwargs.pop(_DVC_COVERAGE_ROOTS_CONFIG_KEY, ())
    dvc_external_covered_paths_value = kwargs.pop(DVC_EXTERNAL_COVERED_PATHS_CONFIG_KEY, ())
    dvc_external_covered_directories_value = kwargs.pop(DVC_EXTERNAL_COVERED_DIRECTORIES_CONFIG_KEY, ())
    if not isinstance(dvc_excluded_paths_value, (list, tuple, set, frozenset)):
        dvc_excluded_paths_value = ()
    dvc_excluded_paths = {
        str(Path(excluded_path).resolve())
        for excluded_path in dvc_excluded_paths_value
        if isinstance(excluded_path, str)
    }
    if not isinstance(dvc_coverage_roots_value, (list, tuple, set, frozenset)):
        dvc_coverage_roots_value = ()
    dvc_coverage_roots = {
        Path(coverage_root).resolve() for coverage_root in dvc_coverage_roots_value if isinstance(coverage_root, str)
    }
    if not isinstance(dvc_external_covered_paths_value, (list, tuple, set, frozenset)):
        dvc_external_covered_paths_value = ()
    dvc_external_covered_paths = {
        str(Path(covered_path).resolve())
        for covered_path in dvc_external_covered_paths_value
        if isinstance(covered_path, str)
    }
    if not isinstance(dvc_external_covered_directories_value, (list, tuple, set, frozenset)):
        dvc_external_covered_directories_value = ()
    dvc_external_covered_directories = {
        str(Path(covered_directory).resolve())
        for covered_directory in dvc_external_covered_directories_value
        if isinstance(covered_directory, str)
    }

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
    aggregate_hash_complete = True
    top_level_hashed_bytes = 0
    nearby_license_cache: dict[str, list[str]] = {}
    pickle_source_snapshot_stack = ExitStack()
    windows_shard_guards: _WindowsShardGuards = []
    directory_shard_targets: ValidatedShardTargets = {}

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
    config = _normalize_repository_inventory_config(config)
    if not is_stream_url(local_source_report_path) and Path(local_source_report_path).name.lower() == "metadata.json":
        from modelaudit.scanners.jax_checkpoint_scanner import JaxCheckpointScanner

        if JaxCheckpointScanner._has_regular_orbax_sibling_marker(Path(local_source_report_path)):
            config[JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY] = True
    directory_owner_snapshot_max_entries_value = config.get(
        "max_directory_owner_snapshot_entries",
        _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES,
    )
    directory_owner_snapshot_max_entries = (
        directory_owner_snapshot_max_entries_value
        if isinstance(directory_owner_snapshot_max_entries_value, int)
        and not isinstance(directory_owner_snapshot_max_entries_value, bool)
        and directory_owner_snapshot_max_entries_value > 0
        else _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES
    )
    local_source_namespace_max_entries = max(
        directory_owner_snapshot_max_entries,
        _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES,
    )
    scanner_selection = policy_from_config(config)
    scanner_selection_extensions = selected_scanner_extensions(scanner_selection) if scanner_selection.active else None
    if scanner_selection.active:
        results.scanner_selection = scanner_selection.to_metadata()

    validate_scan_config(config)
    _finish_phase_timing(phase_timings, "scanner_selection", scanner_selection_started_at)

    # Check if metadata scanner is available once (optimization - avoids loading scanner)
    metadata_scanner_available = scanner_selection.allows("metadata") and _registry.has_scanner_class("MetadataScanner")
    configured_index_context = config.get(_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY)
    index_context_token, index_inspection_context = _activate_safetensors_index_inspection_context(
        configured_index_context if isinstance(configured_index_context, _SafetensorsIndexInspectionContext) else None
    )
    config[_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY] = index_inspection_context

    try:
        if (
            local_source_bound_guard is None
            and expected_local_source_receipt is None
            and not is_stream_url(local_source_report_path)
        ):
            if not os.path.lexists(local_source_report_path):
                raise FileNotFoundError(f"Path does not exist: {local_source_report_path}")
            if os.name == "posix":
                try:
                    owned_local_source_guard = _open_bound_local_source(local_source_report_path)
                except FileNotFoundError:
                    raise
                except (OSError, RuntimeError, ValueError) as error:
                    raise _LocalSourceBoundaryError("local source could not be retained") from error
                local_source_bound_guard = owned_local_source_guard
                expected_local_source_receipt = owned_local_source_guard.receipt
                local_source_boundary_stack.callback(owned_local_source_guard.close)
            elif os.name == "nt":
                expected_local_source_receipt = _snapshot_local_source_receipt(local_source_report_path)
                if expected_local_source_receipt is None:
                    raise _LocalSourceBoundaryError("local source could not be retained")
        if (
            local_source_bound_guard is None
            and expected_local_source_receipt is not None
            and not _local_source_receipts_match(
                expected_local_source_receipt,
                _snapshot_local_source_receipt(local_source_report_path),
            )
        ):
            raise _LocalSourceBoundaryError("local source changed after dispatch")
        if local_source_bound_guard is not None:
            if (
                expected_local_source_receipt is None
                or not _local_source_receipts_match(expected_local_source_receipt, local_source_bound_guard.receipt)
                or local_source_bound_guard.changed()
            ):
                raise _LocalSourceBoundaryError("retained local source changed after dispatch")
            bound_local_source_path = local_source_bound_guard.bound_path
            resolved_path_value = expected_local_source_receipt.get("resolved_path")
            if not isinstance(resolved_path_value, str):
                raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
            resolved_local_source_path = resolved_path_value
            path = bound_local_source_path
            bound_local_source_is_lexical_link = bool(
                local_source_bound_guard.guarded_entries
                and local_source_bound_guard.guarded_entries[-1][3].get("mode_type") == stat.S_IFLNK
            )
            bound_local_source_owner_root_trusted = not bound_local_source_is_lexical_link
            if expected_local_source_receipt.get("mode_type") == stat.S_IFREG:
                config[_BOUND_CACHE_IDENTITY_CONFIG_KEY] = CacheIdentityBinding(
                    scan_path=bound_local_source_path,
                    identity_path=local_source_report_path,
                )
            configured_cache_dir = config.get("cache_dir")
            cache_inside_source = bool(
                expected_local_source_receipt.get("mode_type") == stat.S_IFDIR
                and config.get("cache_enabled", True)
                and isinstance(configured_cache_dir, str)
                and configured_cache_dir
                and is_within_directory(
                    str(Path(local_source_report_path).absolute()),
                    str(Path(configured_cache_dir).absolute()),
                )
            )
            if cache_inside_source:
                raise _LocalSourceBoundaryError("cache directory must be outside the retained local source")
        elif expected_local_source_receipt is not None:
            try:
                local_source_boundary_stack.enter_context(
                    _retain_windows_local_source_guards(
                        local_source_report_path,
                        expected_local_source_receipt,
                    )
                )
                if expected_local_source_receipt.get("mode_type") == stat.S_IFDIR and os.name == "posix":
                    bound_local_source_path = local_source_boundary_stack.enter_context(
                        _bound_local_source_directory(local_source_report_path, expected_local_source_receipt)
                    )
                    resolved_path_value = expected_local_source_receipt.get("resolved_path")
                    if not isinstance(resolved_path_value, str):
                        raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
                    resolved_local_source_path = resolved_path_value
                    path = bound_local_source_path
            except Exception as error:
                raise _LocalSourceBoundaryError("local source boundary could not be retained") from error
        # Handle streaming paths
        if is_stream_url(path):
            # Extract the actual URL
            stream_url = path[9:]  # Remove "stream://" prefix
            report_url = _redacted_stream_url_for_reporting(stream_url)
            if progress_callback:
                progress_callback(f"Streaming analysis: {report_url}", 0.0)

            # Perform streaming analysis
            from modelaudit.scanners import get_scanner_for_file

            scanner = get_scanner_for_file(stream_source_path(stream_url), config=config)
            if scanner:
                if max_file_size > 0:
                    scan_result, analysis_complete = stream_analyze_file(
                        stream_url,
                        scanner,
                        max_bytes=max_file_size,
                    )
                else:
                    scan_result, analysis_complete = stream_analyze_file(stream_url, scanner)
                if scan_result:
                    _redact_stream_scan_result_for_reporting(scan_result, stream_url, report_url)
                    if not analysis_complete:
                        _mark_inconclusive_scan_outcome(scan_result, "streaming_analysis_incomplete")
                    results.files_scanned += 1

                    # Use helper function to add scan result to Pydantic model
                    _add_scan_result_to_model(results, scan_metadata, scan_result, report_url)

                    # Add asset
                    _add_asset_to_results(results, report_url, scan_result)

                    if not analysis_complete:
                        _add_issue_to_model(
                            results,
                            "Streaming analysis incomplete - full scanner coverage was not available",
                            severity=IssueSeverity.INFO.value,
                            location=report_url,
                            details={"analysis_complete": False},
                        )
                else:
                    raise ValueError(f"Streaming analysis failed for {report_url}")
            else:
                raise ValueError(f"No scanner available for {report_url}")

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

        # Check if path is a directory
        if os.path.isdir(path):
            if not os.access(path, os.R_OK):
                raise PermissionError(f"Path is not readable: {path}")

            try:
                local_source_initial_namespace = _capture_directory_owner_namespace(
                    Path(path),
                    None,
                    deadline=start_time + timeout,
                    max_entries=local_source_namespace_max_entries,
                    trusted_root_symlink=bound_local_source_path is not None,
                )
            except (OSError, RuntimeError, TimeoutError) as error:
                local_source_initial_namespace_error = error

            if progress_callback:
                progress_callback(f"Scanning directory: {path}", 0.0)

            # Some model formats are logical directory packages rather than a
            # collection of independently routable files. Run their owning
            # scanner once, then retain the ordinary child walk as supplemental
            # coverage. The child walk owns aggregate physical byte accounting,
            # so the logical package pass records its inspected-byte count only
            # in metadata instead of counting the same files twice.
            directory_owner_result: ScanResult | None = None
            directory_owner_class: type[BaseScanner] | None = None
            directory_owner_source_paths: set[str] = set()
            directory_owner_traversal_sources: set[str] = set()
            directory_owner_unavailable_sources: set[str] = set()
            directory_owner_non_regular_sources: set[str] = set()
            directory_owner_initial_snapshot: tuple[_DirectoryOwnerSnapshotEntry, ...] = ()
            directory_owner_snapshot_failure_reason: str | None = None
            directory_owner_snapshot_failure_details: dict[str, Any] = {}
            directory_owner_snapshot_failure_allows_child_walk = False
            directory_owner_budget_source_paths: set[str] = set()
            directory_owner_content_source_paths: dict[str, str] = {}

            def directory_owner_snapshot_failure(error: Exception) -> tuple[str, dict[str, Any]]:
                if isinstance(error, _DirectoryOwnerSnapshotLimitError):
                    return (
                        "directory_owner_entry_limit",
                        {"max_directory_owner_snapshot_entries": directory_owner_snapshot_max_entries},
                    )
                if isinstance(error, TimeoutError):
                    return "directory_owner_timeout", {"timeout": timeout}
                return "directory_owner_snapshot_incomplete", {"error_type": type(error).__name__}

            def merge_directory_owner_result(owner_result: ScanResult, *, dispatched: bool) -> None:
                owner_bytes_scanned = owner_result.bytes_scanned if dispatched else 0
                if not dispatched:
                    owner_result.metadata.pop("file_size", None)
                owner_result.metadata.update(
                    {
                        "directory_owner_scan": dispatched,
                        "directory_owner_bytes_scanned": owner_bytes_scanned,
                        "aggregate_bytes_accounted_by": "child_file_walk_and_owner_only_sources",
                    }
                )
                owner_result.bytes_scanned = 0
                _add_scan_result_to_model(results, scan_metadata, owner_result, path)
                _add_asset_to_results(results, path, owner_result)

            try:
                directory_owner_class = _registry.get_scanner_for_path(
                    path,
                    scanner_selection=scanner_selection if scanner_selection.active else None,
                )
                if directory_owner_class is None and scanner_selection.active:
                    candidate_owner_class = _registry.get_scanner_for_path(path)
                    if candidate_owner_class is not None:
                        candidate_owner_id = (
                            _registry.get_scanner_id_for_class(candidate_owner_class.__name__)
                            or candidate_owner_class.name
                        )
                        if not scanner_selection.allows(candidate_owner_id):
                            directory_owner_result = make_scanner_selection_skip_result(
                                path,
                                candidate_owner_id,
                                scanner_selection,
                            )
            except Exception as error:
                scanner_name = directory_owner_class.name if directory_owner_class is not None else "directory"
                directory_owner_result = ScanResult(scanner_name=scanner_name)
                directory_owner_result.add_check(
                    name="Directory Owner Scan",
                    passed=False,
                    message=(
                        "Unable to complete logical model-directory analysis: "
                        f"{_redacted_scan_error_for_reporting(error, path)}"
                    ),
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "exception_type": type(error).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": "directory_owner_scan_failed",
                    },
                )
                _mark_inconclusive_scan_outcome(directory_owner_result, "directory_owner_scan_failed")
                _mark_operational_scan_error(directory_owner_result, "directory_owner_scan_failed")
                directory_owner_result.finish(success=False)

            if directory_owner_result is not None:
                merge_directory_owner_result(directory_owner_result, dispatched=False)

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

            base_dir = Path(path).absolute() if bound_local_source_path is not None else Path(path).resolve()

            def logical_local_path(source: str | os.PathLike[str]) -> Path:
                return _local_source_logical_path(
                    source,
                    bound_local_source_path,
                    resolved_local_source_path,
                )

            hf_cache_root = _find_hf_cache_root(
                Path(resolved_local_source_path) if resolved_local_source_path is not None else base_dir
            )
            is_hf_cache = hf_cache_root is not None
            trusted_hf_blobs_root = _trusted_hf_blobs_root(hf_cache_root) if hf_cache_root is not None else None
            scanned_paths: set[str] = set()
            directory_walk_covered_directories: set[str] = set()
            hf_shard_blob_paths: set[str] = set()
            hf_onnx_alias_hash_sources: dict[str, str] = {}
            trusted_hf_alias_scan_paths: set[str] = set()
            trusted_hf_alias_targets: dict[str, dict[str, int | str]] = {}
            trusted_hf_alias_logical_paths: dict[str, str] = {}
            reported_traversal_targets: set[str] = set()

            # First pass: collect all file paths that need scanning
            files_to_scan: list[str] = []
            repository_inventory_files: list[str] = []
            repository_member_by_scan_path: dict[str, str] = {}
            shard_family_representatives: dict[_ShardFamilyKey, str] = {}
            shard_family_paths: dict[_ShardFamilyKey, set[str]] = {}
            shard_family_targets: dict[_ShardFamilyKey, ValidatedShardTargets] = {}
            covered_shard_family_keys: set[_ShardFamilyKey] = set()
            covered_shard_sources: set[str] = set()
            complete_hf_shard_families: set[_ShardFamilyKey] = set()
            trusted_hf_shard_paths: list[str] | None = None
            dvc_directory_output_owners: list[tuple[Path, str]] = []
            pending_dvc_output_limit_checks: list[tuple[str, DvcResolution]] = []
            directory_coverage_gaps: dict[tuple[str, str], set[str]] = {}

            def trusted_hf_owner_source_target(
                owner_source: Path,
                *,
                owner_entry: _DirectoryOwnerSnapshotEntry,
            ) -> Path | None:
                logical_owner_source = _local_source_logical_path(
                    owner_source,
                    bound_local_source_path,
                    resolved_local_source_path,
                )
                if (
                    not is_hf_cache
                    or hf_cache_root is None
                    or trusted_hf_blobs_root is None
                    or owner_entry.entry_type != "link"
                    or not _path_has_part(logical_owner_source, "snapshots")
                ):
                    return None

                def resolve_raw_link_target() -> Path | None:
                    if owner_entry.raw_link_target is None:
                        return None
                    raw_target = Path(owner_entry.raw_link_target)
                    if not raw_target.is_absolute():
                        raw_target = logical_owner_source.parent / raw_target
                    try:
                        return raw_target.resolve(strict=True)
                    except (OSError, RuntimeError):
                        return None

                try:
                    resolved_target = logical_owner_source.resolve(strict=True)
                except (OSError, RuntimeError):
                    raw_resolved_target = resolve_raw_link_target()
                    if raw_resolved_target is None:
                        return None
                    resolved_target = raw_resolved_target
                else:
                    if resolved_target == logical_owner_source.absolute():
                        raw_resolved_target = resolve_raw_link_target()
                        if raw_resolved_target is not None:
                            resolved_target = raw_resolved_target

                try:
                    target_stat = os.stat(resolved_target, follow_symlinks=False)
                except OSError:
                    return None
                if not is_within_directory(str(trusted_hf_blobs_root), str(resolved_target)):
                    return None
                if not stat.S_ISREG(target_stat.st_mode):
                    return None
                return resolved_target

            def get_dvc_directory_roots_by_file() -> dict[str, set[Path]]:
                roots_by_file: dict[str, set[Path]] = {}
                if isinstance(dvc_parent_file, str):
                    roots_by_file[dvc_parent_file] = dvc_coverage_roots or {base_dir}
                for output_dir, owner_dvc_file in dvc_directory_output_owners:
                    roots_by_file.setdefault(owner_dvc_file, set()).add(output_dir)
                return roots_by_file

            def record_dvc_directory_coverage_gap(dvc_file: str, reason: str, failed_path: str) -> None:
                failed_paths = directory_coverage_gaps.setdefault((dvc_file, reason), set())
                if len(failed_paths) < _MAX_DVC_DIRECTORY_COVERAGE_GAPS:
                    failed_paths.add(failed_path)

            def collect_dvc_directory_walk_error(error: OSError) -> None:
                failed_path = error.filename if isinstance(error.filename, str) else path
                for affected_dvc_file, output_roots in get_dvc_directory_roots_by_file().items():
                    if any(is_within_directory(str(output_root), failed_path) for output_root in output_roots):
                        record_dvc_directory_coverage_gap(
                            affected_dvc_file,
                            _DVC_DIRECTORY_WALK_FAILED_REASON,
                            failed_path,
                        )

            def resolve_covered_dvc_file_symlink(file_path: Path) -> Path | None:
                roots_by_file = get_dvc_directory_roots_by_file()
                if not roots_by_file or not file_path.is_symlink():
                    return None
                try:
                    resolved_target = file_path.resolve(strict=True)
                except (OSError, RuntimeError):
                    return None
                absolute_symlink_path = Path(os.path.abspath(file_path))
                for output_roots in roots_by_file.values():
                    link_is_declared = any(absolute_symlink_path.is_relative_to(root) for root in output_roots)
                    target_is_declared = any(
                        is_within_directory(str(root), str(resolved_target)) for root in output_roots
                    )
                    if link_is_declared and target_is_declared:
                        return resolved_target
                return None

            def record_uncovered_dvc_file_symlink(file_path: Path, resolved_target: Path | None) -> None:
                if not file_path.is_symlink():
                    return
                absolute_symlink_path = Path(os.path.abspath(file_path))
                for affected_dvc_file, output_roots in get_dvc_directory_roots_by_file().items():
                    if not any(absolute_symlink_path.is_relative_to(root) for root in output_roots):
                        continue
                    if resolved_target is not None and any(
                        is_within_directory(str(root), str(resolved_target)) for root in output_roots
                    ):
                        continue
                    record_dvc_directory_coverage_gap(
                        affected_dvc_file,
                        _DVC_DIRECTORY_SYMLINK_UNSCANNED_REASON,
                        str(file_path),
                    )

            def record_dvc_directory_special_file(file_path: Path) -> bool:
                absolute_path = Path(os.path.abspath(file_path))
                recorded = False
                for affected_dvc_file, output_roots in get_dvc_directory_roots_by_file().items():
                    if not any(absolute_path.is_relative_to(root) for root in output_roots):
                        continue
                    record_dvc_directory_coverage_gap(
                        affected_dvc_file,
                        _DVC_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON,
                        str(file_path),
                    )
                    recorded = True
                return recorded

            def record_non_regular_directory_entry(file_path: Path) -> None:
                nonlocal aggregate_hash_complete
                aggregate_hash_complete = False
                scan_metadata["success"] = False
                scan_metadata["has_operational_errors"] = True
                _add_issue_to_model(
                    results,
                    "Non-regular directory entry was not scanned",
                    severity=IssueSeverity.INFO.value,
                    location=str(file_path),
                    details={
                        "entry_type": "non_regular",
                        "analysis_incomplete": True,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": "directory_entry_non_regular",
                    },
                )

            def record_owner_unscanned_entry(
                file_path: Path,
                owner_entry: _DirectoryOwnerSnapshotEntry,
            ) -> None:
                nonlocal aggregate_hash_complete
                if record_dvc_directory_special_file(file_path):
                    return
                if owner_entry.entry_type == "link":
                    record_non_regular_directory_entry(file_path)
                    return
                aggregate_hash_complete = False
                _record_directory_special_file_unscanned(results, scan_metadata, str(file_path))

            def repository_member_path_for_discovered_path(scan_path: str | Path) -> str | None:
                with suppress(OSError, RuntimeError, ValueError):
                    relative_path = Path(scan_path).absolute().relative_to(base_dir).as_posix()
                    normalized_relative = normalize_repository_member_path(relative_path)
                    if normalized_relative is not None:
                        return normalized_relative
                return _repository_member_path_for_scan(str(scan_path), base_dir)

            directory_discovery_started_at = _start_phase_timing(phase_timings)
            owner_root_path = Path(os.path.abspath(path))
            if directory_owner_class is not None and directory_owner_result is None:
                try:
                    directory_owner_initial_snapshot = _capture_directory_owner_namespace(
                        owner_root_path,
                        directory_owner_class,
                        deadline=start_time + timeout,
                        max_entries=directory_owner_snapshot_max_entries,
                        trusted_root_symlink=bound_local_source_owner_root_trusted,
                    )
                except (OSError, RuntimeError, TimeoutError) as error:
                    (
                        directory_owner_snapshot_failure_reason,
                        directory_owner_snapshot_failure_details,
                    ) = directory_owner_snapshot_failure(error)
                    directory_owner_snapshot_failure_allows_child_walk = (
                        directory_owner_snapshot_failure_reason == "directory_owner_snapshot_incomplete"
                    )
                    if directory_owner_snapshot_failure_allows_child_walk:
                        directory_owner_snapshot_failure_details["child_walk_continued"] = True
                    logger.warning(
                        "Unable to capture initial logical directory-owner namespace for %s: %s",
                        path,
                        error,
                    )
                else:
                    for owner_entry in directory_owner_initial_snapshot:
                        owner_source = str(owner_root_path.joinpath(*owner_entry.relative_parts))
                        if owner_entry.entry_type == "file":
                            directory_owner_source_paths.add(owner_source)
                            if directory_owner_class.directory_owner_source_counts_toward_limits(
                                owner_entry.relative_parts,
                            ):
                                directory_owner_budget_source_paths.add(owner_source)
                        elif owner_entry.entry_type != "directory":
                            trusted_target = trusted_hf_owner_source_target(
                                Path(owner_source),
                                owner_entry=owner_entry,
                            )
                            if trusted_target is None:
                                directory_owner_non_regular_sources.add(owner_source)
                            else:
                                directory_owner_source_paths.add(owner_source)
                                directory_owner_content_source_paths[owner_source] = str(trusted_target)
                                if directory_owner_class.directory_owner_source_counts_toward_limits(
                                    owner_entry.relative_parts,
                                ):
                                    directory_owner_budget_source_paths.add(owner_source)

            if local_source_initial_namespace_error is not None:
                if directory_owner_class is None:
                    raise _LocalSourceBoundaryError("local source namespace could not be retained") from (
                        local_source_initial_namespace_error
                    )
                if directory_owner_snapshot_failure_reason is None:
                    (
                        directory_owner_snapshot_failure_reason,
                        directory_owner_snapshot_failure_details,
                    ) = directory_owner_snapshot_failure(local_source_initial_namespace_error)
                directory_owner_snapshot_failure_allows_child_walk = False

            initial_owner_entries = {entry.relative_parts: entry for entry in directory_owner_initial_snapshot}
            initial_local_source_entries = {
                entry.relative_parts: entry for entry in local_source_initial_namespace or ()
            }
            observed_local_source_entries: set[tuple[str, ...]] = (
                {()} if local_source_initial_namespace is not None else set()
            )

            def validate_local_source_walk_entry(entry_path: Path, relative_parts: tuple[str, ...]) -> None:
                expected_entry = initial_local_source_entries.get(relative_parts)
                try:
                    current_stat = os.stat(entry_path) if not relative_parts else entry_path.lstat()
                    current_entry = _directory_owner_snapshot_entry(
                        entry_path,
                        relative_parts,
                        entry_stat=current_stat,
                    )
                except OSError as error:
                    raise _LocalSourceBoundaryError("local source entry changed during discovery") from error
                if not _directory_owner_snapshot_entries_match(expected_entry, current_entry):
                    raise _LocalSourceBoundaryError("local source entry changed during discovery")
                observed_local_source_entries.add(relative_parts)

            directory_walk_skipped = bool(
                directory_owner_snapshot_failure_reason is not None
                and not directory_owner_snapshot_failure_allows_child_walk
            )
            directory_walk = (
                ()
                if directory_walk_skipped
                else os.walk(
                    path,
                    followlinks=False,
                    onerror=collect_dvc_directory_walk_error,
                )
            )
            for root, dirs, files in directory_walk:
                root_path = Path(root)
                root_relative_parts = Path(os.path.relpath(root_path, path)).parts
                if root_relative_parts == (".",):
                    root_relative_parts = ()
                validate_local_source_walk_entry(root_path, root_relative_parts)
                for child_name in [*dirs, *files]:
                    validate_local_source_walk_entry(
                        root_path / child_name,
                        (*root_relative_parts, child_name),
                    )
                dirs.sort()
                directory_walk_covered_directories.add(str(Path(root).resolve()))
                unclassified_symlinks = _unclassified_symlink_names(root, dirs, files)
                if unclassified_symlinks:
                    unclassified_symlink_set = set(unclassified_symlinks)
                    dirs[:] = [directory for directory in dirs if directory not in unclassified_symlink_set]
                candidate_files = sorted([*files, *unclassified_symlinks])
                for file in candidate_files:
                    file_path = os.path.join(root, file)

                    # HuggingFace cache bookkeeping files should never surface as
                    # scan assets or SBOM components for downloaded models.
                    if _is_huggingface_cache_file(file_path):
                        logger.debug(f"Skipping HuggingFace cache file: {file_path}")
                        continue

                    file_path_obj = Path(file_path)
                    relative_parts = Path(os.path.relpath(file_path_obj, path)).parts
                    is_directory_owner_source = bool(
                        directory_owner_class is not None
                        and ".." not in relative_parts
                        and directory_owner_class.directory_owner_source_in_scope(relative_parts)
                    )
                    initial_owner_entry = initial_owner_entries.get(relative_parts)
                    if (
                        is_directory_owner_source
                        and initial_owner_entry is not None
                        and initial_owner_entry.entry_type != "file"
                        and str(Path(os.path.abspath(file_path_obj))) not in directory_owner_content_source_paths
                    ):
                        record_owner_unscanned_entry(file_path_obj, initial_owner_entry)
                        continue
                    if not file_path_obj.is_file() and not file_path_obj.is_symlink():
                        if is_directory_owner_source:
                            directory_owner_unavailable_sources.add(str(file_path_obj))
                        if not record_dvc_directory_special_file(file_path_obj):
                            aggregate_hash_complete = False
                            _record_directory_special_file_unscanned(results, scan_metadata, file_path)
                        continue
                    resolved_file = resolve_covered_dvc_file_symlink(file_path_obj)
                    is_dvc_covered_file_symlink = resolved_file is not None
                    is_hf_cache_symlink = False
                    logical_file_path = _local_source_logical_path(
                        file_path_obj,
                        bound_local_source_path,
                        resolved_local_source_path,
                    )
                    if resolved_file is None:
                        resolved_file, is_hf_cache_symlink, entry_unavailable = _resolve_directory_scan_target(
                            file_path_obj,
                            base_dir,
                            is_hf_cache=is_hf_cache,
                            hf_cache_root=hf_cache_root,
                            results=results,
                            reported_traversal_targets=reported_traversal_targets,
                            preserve_bound_path=bound_local_source_path is not None,
                            hf_snapshot_path=logical_file_path,
                        )
                        if entry_unavailable:
                            scan_metadata["success"] = False
                            scan_metadata["has_operational_errors"] = True
                    record_uncovered_dvc_file_symlink(file_path_obj, resolved_file)
                    if resolved_file is None:
                        if is_directory_owner_source:
                            if entry_unavailable:
                                directory_owner_unavailable_sources.add(str(file_path_obj))
                            else:
                                directory_owner_traversal_sources.add(str(file_path_obj))
                        continue
                    if not resolved_file.is_file():
                        if is_directory_owner_source:
                            directory_owner_unavailable_sources.add(str(file_path_obj))
                        if not record_dvc_directory_special_file(file_path_obj):
                            record_non_regular_directory_entry(file_path_obj)
                        continue
                    trusted_owner_content_source = directory_owner_content_source_paths.get(
                        str(Path(os.path.abspath(file_path_obj)))
                    )
                    if (
                        is_directory_owner_source
                        and trusted_owner_content_source is not None
                        and str(resolved_file) == trusted_owner_content_source
                    ):
                        continue
                    if not resolved_file.is_file():
                        aggregate_hash_complete = False
                        _record_directory_special_file_unscanned(results, scan_metadata, file_path)
                        continue
                    repository_member = repository_member_path_for_discovered_path(file_path_obj)
                    if repository_member is not None:
                        repository_inventory_files.append(repository_member)
                    snapshot_path = Path(file_path).absolute()
                    snapshot_shard_family_key = _shard_family_key_for_path(str(snapshot_path))
                    route_hf_shard_alias = (
                        is_hf_cache_symlink and resolved_file.exists() and snapshot_shard_family_key is not None
                    )
                    route_hf_onnx_alias = is_hf_cache_symlink and _should_scan_hf_cache_alias_lexically_for_onnx(
                        logical_file_path,
                        hf_cache_root,
                    )
                    scan_source = (
                        snapshot_path
                        if is_hf_cache_symlink
                        and (bound_local_source_path is not None or route_hf_shard_alias or route_hf_onnx_alias)
                        else resolved_file
                    )

                    # Skip non-model files early if filtering is enabled
                    # Note: skip_file_types parameter already contains the correct value
                    if (
                        skip_file_types
                        and should_skip_file(
                            file_path,
                            metadata_scanner_available=metadata_scanner_available,
                            scanner_selection_extensions=scanner_selection_extensions,
                        )
                        and not _preserve_hf_download_sidecar_asset(file_path, scanner_selection_extensions)
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
                    target_paths = [scan_source]
                    dvc_pointer_file: str | None = None
                    if file.lower().endswith(".dvc"):
                        dvc_pointer_file = file_path
                        dvc_resolution = resolve_dvc_file_status(file_path)
                        if dvc_resolution.has_non_cap_gap:
                            _record_incomplete_dvc_resolution(results, scan_metadata, file_path, dvc_resolution)
                            aggregate_hash_complete = False
                        elif dvc_resolution.omitted_output_count > 0:
                            pending_dvc_output_limit_checks.append((file_path, dvc_resolution))
                        if dvc_resolution.resolved_paths:
                            target_paths = [Path(t).resolve() for t in dvc_resolution.resolved_paths]
                        else:
                            continue

                    for target_path in target_paths:
                        # The root walk already discovers files below resolved DVC
                        # directory outputs. Do not queue the directory as a file.
                        if target_path.is_dir():
                            if dvc_pointer_file is not None:
                                dvc_directory_output_owners.append((target_path, dvc_pointer_file))
                            continue

                        target_str = str(target_path)
                        target_repository_member = (
                            repository_member
                            if target_path == scan_source
                            else _repository_member_path_for_scan(target_str, base_dir)
                        )
                        if target_repository_member is not None:
                            repository_member_by_scan_path[target_str] = target_repository_member
                        logical_target_str = str(
                            _local_source_logical_path(
                                target_str,
                                bound_local_source_path,
                                resolved_local_source_path,
                            )
                        )
                        shard_family_key = _shard_family_key_for_path(logical_target_str)
                        is_hf_shard_alias = route_hf_shard_alias and target_path == scan_source
                        exclusion_path = (
                            str(resolved_file)
                            if is_hf_cache_symlink and target_path == scan_source
                            else _resolve_or_absolute_path(target_str)
                        )
                        if exclusion_path in dvc_excluded_paths:
                            continue
                        if is_hf_shard_alias:
                            hf_shard_blob_paths.add(str(resolved_file))
                        if is_hf_cache_symlink and target_path == scan_source:
                            trusted_hf_alias_scan_paths.add(target_str)
                            trusted_hf_alias_logical_paths[target_str] = str(logical_file_path)
                            alias_target = _snapshot_regular_file_target(resolved_file)
                            if alias_target is not None:
                                trusted_hf_alias_targets[target_str] = alias_target
                        is_hf_onnx_alias = route_hf_onnx_alias and target_path == scan_source
                        if is_hf_onnx_alias and bound_local_source_path is None:
                            hf_onnx_alias_hash_sources[target_str] = str(resolved_file)
                        dedupe_target_str = (
                            str(resolved_file)
                            if (
                                is_hf_cache_symlink
                                and target_path == scan_source
                                and shard_family_key is None
                                and not is_hf_onnx_alias
                            )
                            else target_str
                        )
                        if dedupe_target_str in scanned_paths:
                            continue
                        scanned_paths.add(dedupe_target_str)

                        if (
                            not is_hf_cache_symlink
                            and not is_dvc_covered_file_symlink
                            and not is_within_directory(str(base_dir), str(target_path))
                        ):
                            _add_path_traversal_issue_once(
                                results,
                                location=str(target_path),
                                resolved_path=str(target_path),
                                reported_targets=reported_traversal_targets,
                            )
                            continue

                        # Add to files to scan list instead of scanning immediately
                        if shard_family_key is not None:
                            raw_shard_family_key = shard_family_key
                            normalized_shard_source = os.path.normcase(
                                os.path.normpath(os.path.abspath(logical_target_str))
                            )
                            if (
                                raw_shard_family_key in covered_shard_family_keys
                                or normalized_shard_source in covered_shard_sources
                            ):
                                continue
                            shard_is_in_hf_snapshot = bool(
                                is_hf_cache
                                and hf_cache_root is not None
                                and _path_has_part(
                                    _local_source_logical_path(
                                        target_str,
                                        bound_local_source_path,
                                        resolved_local_source_path,
                                    ),
                                    "snapshots",
                                )
                            )
                            allowed_hf_shard_paths = None
                            if shard_is_in_hf_snapshot and hf_cache_root is not None:
                                if trusted_hf_shard_paths is None:
                                    trusted_hf_shard_paths = _allowed_hf_shard_alias_paths(base_dir, hf_cache_root)
                                allowed_hf_shard_paths = trusted_hf_shard_paths
                            shard_info = ShardedModelDetector.detect_shards(
                                logical_target_str,
                                allowed_paths=allowed_hf_shard_paths,
                                index_search_root=(
                                    Path(resolved_local_source_path)
                                    if resolved_local_source_path is not None
                                    else base_dir
                                ),
                            )
                            covered_shard_family_keys.add(raw_shard_family_key)
                            if shard_info is not None and not shard_info.get("safetensors_index_error"):
                                governing_index = shard_info.get("safetensors_index_path")
                                pattern = shard_info.get("pattern")
                                expected_total = shard_info.get("expected_total_shards")
                                if (
                                    isinstance(governing_index, str)
                                    and isinstance(pattern, str)
                                    and isinstance(expected_total, int)
                                ):
                                    shard_family_key = (
                                        f"index:{os.path.normcase(os.path.normpath(os.path.abspath(governing_index)))}",
                                        pattern,
                                        expected_total,
                                    )
                            if shard_family_key not in shard_family_representatives:
                                shard_family_representatives[shard_family_key] = logical_target_str
                                family_paths = shard_family_paths.setdefault(shard_family_key, set())
                                if shard_info is None:
                                    family_paths.add(logical_target_str)
                                else:
                                    validated_targets: ValidatedShardTargets = {}
                                    detected_targets = shard_info.get("shard_targets")
                                    expected_total_shards = shard_info.get("expected_total_shards")
                                    index_base = shard_info.get("shard_index_base")
                                    index_path = shard_info.get("safetensors_index_path")
                                    index_fingerprint = shard_info.get("safetensors_index_fingerprint")
                                    index_generation = shard_info.get("safetensors_index_generation")
                                    authoritative_index_fields: dict[str, int | str] = {}
                                    if (
                                        isinstance(index_base, str)
                                        and index_base in {"zero", "one"}
                                        and isinstance(index_path, str)
                                        and index_path
                                        and isinstance(index_fingerprint, str)
                                        and index_fingerprint
                                        and isinstance(index_generation, int)
                                        and not isinstance(index_generation, bool)
                                        and index_generation > 0
                                    ):
                                        authoritative_index_fields = {
                                            "authoritative_shard_index_base": index_base,
                                            "authoritative_shard_index_path": os.path.normcase(
                                                os.path.normpath(os.path.abspath(index_path))
                                            ),
                                            "authoritative_shard_index_fingerprint": index_fingerprint,
                                            "authoritative_shard_index_generation": index_generation,
                                        }
                                    for shard_path in shard_info.get("shards", []):
                                        if not isinstance(shard_path, str) or not isinstance(detected_targets, dict):
                                            continue
                                        detected_target = detected_targets.get(shard_path)
                                        if not isinstance(detected_target, dict):
                                            continue
                                        resolved_shard_path = detected_target.get("resolved_path")
                                        if not isinstance(resolved_shard_path, str):
                                            continue
                                        shard_in_base_dir = is_within_directory(str(base_dir), resolved_shard_path)
                                        shard_in_hf_blobs = bool(
                                            trusted_hf_blobs_root is not None
                                            and is_within_directory(
                                                str(trusted_hf_blobs_root),
                                                resolved_shard_path,
                                            )
                                        )
                                        if shard_in_base_dir or shard_in_hf_blobs:
                                            lexical_shard_path = str(Path(shard_path).absolute())
                                            _retain_windows_shard_guard(
                                                windows_shard_guards,
                                                resolved_shard_path,
                                                lexical_shard_path,
                                                detected_target,
                                            )
                                            covered_shard_sources.add(
                                                os.path.normcase(os.path.normpath(os.path.abspath(lexical_shard_path)))
                                            )
                                            family_paths.add(lexical_shard_path)
                                            shard_repository_member = repository_member_path_for_discovered_path(
                                                lexical_shard_path
                                            )
                                            if shard_repository_member is not None:
                                                repository_member_by_scan_path[lexical_shard_path] = (
                                                    shard_repository_member
                                                )
                                            validated_targets[lexical_shard_path] = {
                                                **authoritative_index_fields,
                                                **{
                                                    key: value
                                                    for key, value in detected_target.items()
                                                    if key
                                                    in {
                                                        "resolved_path",
                                                        "device",
                                                        "inode",
                                                        "size",
                                                        "mtime_ns",
                                                        "ctime_ns",
                                                        "nlink",
                                                    }
                                                    and isinstance(value, (int, str))
                                                },
                                            }
                                        else:
                                            _add_path_traversal_issue_once(
                                                results,
                                                location=shard_path,
                                                resolved_path=resolved_shard_path,
                                                reported_targets=reported_traversal_targets,
                                            )
                                    shard_family_targets[shard_family_key] = validated_targets
                                    directory_shard_targets.update(validated_targets)
                                    incomplete_count_keys = (
                                        "missing_shard_count",
                                        "unreadable_shard_count",
                                        "out_of_scope_shard_count",
                                        "unvalidated_shard_count",
                                        "duplicate_shard_count",
                                        "unexpected_shard_count",
                                    )
                                    if (
                                        shard_is_in_hf_snapshot
                                        and isinstance(expected_total_shards, int)
                                        and shard_info.get("total_shards") == expected_total_shards
                                        and not any(shard_info.get(key, 0) for key in incomplete_count_keys)
                                    ):
                                        complete_hf_shard_families.add(shard_family_key)
                                    for shard_path in shard_info.get("out_of_scope_shards", []):
                                        if isinstance(shard_path, str):
                                            resolved_shard_path = _resolve_discovered_shard_path(shard_path, results)
                                            if resolved_shard_path is None:
                                                continue
                                            if not is_within_directory(str(base_dir), resolved_shard_path):
                                                _add_path_traversal_issue_once(
                                                    results,
                                                    location=resolved_shard_path,
                                                    resolved_path=resolved_shard_path,
                                                    reported_targets=reported_traversal_targets,
                                                )
                            continue

                        files_to_scan.append(target_str)

                if isinstance(dvc_parent_file, str) or dvc_directory_output_owners:
                    dvc_directory_roots_by_file = get_dvc_directory_roots_by_file()
                    for directory_name in tuple(dirs):
                        symlink_dir = Path(root) / directory_name
                        if not _is_directory_link(symlink_dir):
                            continue
                        dirs.remove(directory_name)
                        symlink_path = Path(os.path.abspath(symlink_dir))
                        for affected_dvc_file, output_roots in dvc_directory_roots_by_file.items():
                            if not any(symlink_path.is_relative_to(output_root) for output_root in output_roots):
                                continue
                            try:
                                resolved_symlink = symlink_dir.resolve(strict=True)
                            except (OSError, RuntimeError):
                                resolved_symlink = None
                            if resolved_symlink is not None and any(
                                is_within_directory(str(output_root), str(resolved_symlink))
                                for output_root in output_roots
                            ):
                                continue
                            record_dvc_directory_coverage_gap(
                                affected_dvc_file,
                                _DVC_DIRECTORY_SYMLINK_UNSCANNED_REASON,
                                str(symlink_dir),
                            )

            if not directory_walk_skipped and observed_local_source_entries != set(initial_local_source_entries):
                raise _LocalSourceBoundaryError("local source namespace was not fully traversed")

            for (affected_dvc_file, incomplete_reason), failed_paths in directory_coverage_gaps.items():
                aggregate_hash_complete = False
                _record_incomplete_dvc_resolution(
                    results,
                    scan_metadata,
                    affected_dvc_file,
                    DvcResolution(
                        unresolved_outputs=tuple(sorted(failed_paths)),
                        incomplete_reason=incomplete_reason,
                    ),
                )
            _finish_phase_timing(phase_timings, "directory_discovery", directory_discovery_started_at)

            if hf_shard_blob_paths:
                files_to_scan = [
                    file_path
                    for file_path in files_to_scan
                    if _resolve_or_absolute_path(file_path) not in hf_shard_blob_paths
                ]
            scan_entries: list[_ScanEntry] = [
                (file_path, [file_path], None, repository_member_by_scan_path.get(file_path))
                for file_path in files_to_scan
            ]
            seen_complete_hf_shard_families: set[tuple[str, tuple[str, ...]]] = set()
            for shard_family_key, representative_file in shard_family_representatives.items():
                ordered_family_paths = sorted(shard_family_paths.get(shard_family_key, {representative_file}))
                expected_total_shards = shard_family_key[2]
                if (
                    is_hf_cache
                    and expected_total_shards is not None
                    and shard_family_key in complete_hf_shard_families
                    and len(ordered_family_paths) == expected_total_shards
                ):
                    family_targets = shard_family_targets.get(shard_family_key, {})
                    resolved_family_paths = tuple(
                        sorted(
                            str(family_targets.get(path, {}).get("resolved_path", _resolve_or_absolute_path(path)))
                            for path in ordered_family_paths
                        )
                    )
                    family_dedupe_key = (shard_family_key[1], resolved_family_paths)
                    if family_dedupe_key in seen_complete_hf_shard_families:
                        continue
                    seen_complete_hf_shard_families.add(family_dedupe_key)
                scan_entries.append(
                    (
                        representative_file,
                        ordered_family_paths,
                        shard_family_key,
                        repository_member_by_scan_path.get(representative_file),
                    )
                )

            covered_openvino_companion_sizes: dict[str, int] = {}
            if scanner_selection.allows("openvino"):
                covered_companions_by_key: dict[str, str] = {}
                for (
                    representative_file,
                    _scanned_file_paths,
                    _entry_shard_family_key,
                    _repository_member,
                ) in scan_entries:
                    xml_path = logical_local_path(representative_file)
                    companion_path = _openvino_xml_weights_companion(xml_path)
                    if companion_path is None:
                        continue
                    companion_snapshot = _snapshot_openvino_companion_for_hash(xml_path, companion_path)
                    if companion_snapshot is None:
                        aggregate_hash_complete = False
                        continue
                    if _openvino_weights_sidecar_needs_independent_scan(companion_path, scanner_selection):
                        continue
                    xml_key = _openvino_xml_companion_key(xml_path)
                    companion_path_str = str(companion_path)
                    covered_openvino_companion_sizes[xml_key] = _snapshot_file_size(companion_snapshot)
                    covered_companions_by_key[_openvino_xml_companion_key(companion_path)] = companion_path_str

                if covered_companions_by_key:
                    expanded_scan_entries: list[_ScanEntry] = []
                    for (
                        representative_file,
                        scanned_file_paths,
                        entry_shard_family_key,
                        repository_member,
                    ) in scan_entries:
                        representative_key = _openvino_xml_companion_key(logical_local_path(representative_file))
                        if representative_key in covered_companions_by_key:
                            continue

                        expanded_scanned_file_paths = list(scanned_file_paths)
                        expanded_scanned_path_keys = {
                            _openvino_xml_companion_key(logical_local_path(scanned_file_path))
                            for scanned_file_path in expanded_scanned_file_paths
                        }
                        companion_path = _openvino_xml_weights_companion(logical_local_path(representative_file))
                        if companion_path is not None:
                            companion_key = _openvino_xml_companion_key(companion_path)
                            covered_companion_path = covered_companions_by_key.get(companion_key)
                            if covered_companion_path is not None and companion_key not in expanded_scanned_path_keys:
                                expanded_scanned_file_paths.append(covered_companion_path)
                        expanded_scan_entries.append(
                            (
                                representative_file,
                                expanded_scanned_file_paths,
                                entry_shard_family_key,
                                repository_member,
                            )
                        )
                    scan_entries = expanded_scan_entries

            if isinstance(dvc_parent_file, str) and isinstance(dvc_remaining_total_size, int):
                remaining_size = dvc_remaining_total_size
                bounded_scan_entries: list[_ScanEntry] = []
                dvc_budget_exhausted = remaining_size < 0
                for scan_entry in scan_entries:
                    if dvc_budget_exhausted:
                        break
                    try:
                        entry_size = sum(os.path.getsize(file_path) for file_path in scan_entry[1])
                    except OSError:
                        dvc_budget_exhausted = True
                        break
                    if entry_size > remaining_size:
                        dvc_budget_exhausted = True
                        break
                    bounded_scan_entries.append(scan_entry)
                    remaining_size -= entry_size

                scan_entries = bounded_scan_entries
                if dvc_budget_exhausted:
                    aggregate_hash_complete = False
                    limit_reached = True
                    _record_incomplete_dvc_scan_budget(
                        results,
                        scan_metadata,
                        dvc_parent_file,
                        budget_type="total_size",
                        limit=dvc_total_size_limit if isinstance(dvc_total_size_limit, int) else max_total_size,
                    )

            if not isinstance(config.get(REPOSITORY_FILE_INVENTORY_CONFIG_KEY), RepositoryFileInventory):
                if REPOSITORY_FILE_INVENTORY_CONFIG_KEY not in config:
                    config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = tuple(repository_inventory_files)
                config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = repository_file_inventory_context_from_config(config)
            repository_inventory_context = config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY]

            owner_sources = sorted(directory_owner_source_paths)
            owner_budget_sources = sorted(directory_owner_budget_source_paths)

            def owner_content_source(owner_source: str) -> str:
                return directory_owner_content_source_paths.get(owner_source, owner_source)

            def owner_hash_for_source(hashes: dict[str, str], owner_source: str) -> str | None:
                return hashes.get(owner_source) or hashes.get(owner_content_source(owner_source))

            def owner_hash_missing_or_deferred(hashes: dict[str, str], owner_source: str) -> bool:
                hash_value = owner_hash_for_source(hashes, owner_source)
                return hash_value is None or hash_value.startswith(
                    ("unhashable_max_file_size_", "unhashable_max_total_size_"),
                )

            owner_block_reason: str | None = None
            owner_block_details: dict[str, Any] = {}
            owner_sizes: dict[str, int] = {}
            owner_budget_total_size = 0
            invalidated_owner_relative_parts: set[tuple[str, ...]] = set()
            if directory_owner_class is not None and directory_owner_result is None:
                if directory_owner_snapshot_failure_reason is not None:
                    owner_block_reason = directory_owner_snapshot_failure_reason
                    owner_block_details = directory_owner_snapshot_failure_details
                elif directory_owner_non_regular_sources:
                    owner_block_reason = "directory_owner_source_not_regular"
                    owner_block_details = {
                        "non_regular_source_count": len(directory_owner_non_regular_sources),
                    }
                elif directory_owner_traversal_sources:
                    owner_block_reason = "directory_owner_path_traversal"
                    owner_block_details = {
                        "traversal_source_count": len(directory_owner_traversal_sources),
                    }
                elif directory_owner_unavailable_sources:
                    owner_block_reason = "directory_owner_source_unavailable"
                    owner_block_details = {
                        "unavailable_source_count": len(directory_owner_unavailable_sources),
                    }
                else:
                    try:
                        for source in owner_sources:
                            source_stat = os.stat(owner_content_source(source), follow_symlinks=False)
                            if not stat.S_ISREG(source_stat.st_mode):
                                raise OSError(f"Directory owner source is not a regular file: {source}")
                            owner_sizes[source] = source_stat.st_size
                        owner_budget_total_size = sum(owner_sizes[source] for source in owner_budget_sources)
                    except OSError as error:
                        owner_block_reason = "directory_owner_source_unavailable"
                        owner_block_details = {"error_type": type(error).__name__}
                if owner_block_reason is None and max_file_size > 0:
                    oversized_sources = [
                        source for source in owner_budget_sources if owner_sizes[source] > max_file_size
                    ]
                    if oversized_sources:
                        owner_block_reason = "directory_owner_max_file_size"
                        owner_block_details = {
                            "max_file_size": max_file_size,
                            "oversized_source_count": len(oversized_sources),
                        }
                if owner_block_reason is None and max_total_size > 0 and owner_budget_total_size > max_total_size:
                    owner_block_reason = "directory_owner_max_total_size"
                    owner_block_details = {
                        "max_total_size": max_total_size,
                        "owner_source_bytes": owner_budget_total_size,
                    }
                if owner_block_reason is None and time.time() - start_time > timeout:
                    owner_block_reason = "directory_owner_timeout"
                    owner_block_details = {"timeout": timeout}
                if owner_block_reason is None:
                    try:
                        owner_snapshot_before_hash = _capture_directory_owner_namespace(
                            owner_root_path,
                            directory_owner_class,
                            deadline=start_time + timeout,
                            max_entries=directory_owner_snapshot_max_entries,
                            trusted_root_symlink=bound_local_source_owner_root_trusted,
                        )
                    except (OSError, RuntimeError, TimeoutError) as error:
                        owner_block_reason, owner_block_details = directory_owner_snapshot_failure(error)
                    else:
                        changed_owner_relative_parts = _directory_owner_snapshot_changed_paths(
                            directory_owner_initial_snapshot,
                            owner_snapshot_before_hash,
                        )
                        if changed_owner_relative_parts:
                            invalidated_owner_relative_parts.update(changed_owner_relative_parts)
                            owner_block_reason = "directory_owner_source_changed"
                            owner_block_details = {"changed_source_count": len(changed_owner_relative_parts)}

            def owner_relative_parts_for_scan_path(scan_path: str) -> tuple[str, ...] | None:
                absolute_scan_path = Path(os.path.abspath(scan_path))
                for candidate_root in (owner_root_path, base_dir):
                    try:
                        return absolute_scan_path.relative_to(candidate_root).parts
                    except ValueError:
                        continue
                return None

            def scan_entry_has_invalidated_owner_source(scan_entry: _ScanEntry) -> bool:
                return any(owner_scan_path_is_invalidated(scanned_path) for scanned_path in scan_entry[1])

            def owner_scan_path_is_invalidated(scan_path: str) -> bool:
                relative_parts = owner_relative_parts_for_scan_path(scan_path)
                if relative_parts is None:
                    return False
                return any(
                    relative_parts[: len(invalidated_parts)] == invalidated_parts
                    for invalidated_parts in invalidated_owner_relative_parts
                )

            if invalidated_owner_relative_parts:
                scan_entries = [entry for entry in scan_entries if not scan_entry_has_invalidated_owner_source(entry)]

            # Second pass: scan every non-shard path independently and every shard
            # family once. Shard scans already expand to sibling shards in the
            # advanced handler, so scanning each shard path would duplicate work.
            if scan_entries or (directory_owner_class is not None and directory_owner_result is None):
                covered_openvino_xml_companions = set(covered_openvino_companion_sizes)
                hash_sources: list[str] = []
                seen_hash_sources: set[str] = set()
                hash_source_by_path: dict[str, str] = {}
                hash_budget_bytes = 0
                onnx_external_data_sources_by_path: dict[str, list[str]] = {}
                onnx_external_data_sizes_by_path: dict[str, int] = {}
                onnx_external_data_routing_paths: dict[str, str] = {}
                scan_entry_target_keys: set[_FileTargetIdentityKey] = set()
                for (
                    _representative_file,
                    scanned_file_paths,
                    _entry_shard_family_key,
                    _repository_member,
                ) in scan_entries:
                    for scanned_file_path in scanned_file_paths:
                        scanned_path = Path(scanned_file_path)
                        scanned_identity = _snapshot_file_identity(scanned_path)
                        scanned_target_key = _file_target_identity_key(scanned_path, scanned_identity)
                        if scanned_target_key is not None:
                            scan_entry_target_keys.add(scanned_target_key)
                for (
                    representative_file,
                    scanned_file_paths,
                    entry_shard_family_key,
                    _repository_member,
                ) in scan_entries:
                    family_targets = (
                        shard_family_targets.get(entry_shard_family_key, {})
                        if entry_shard_family_key is not None
                        else {}
                    )
                    for scanned_file_path in scanned_file_paths:
                        hash_source = hf_onnx_alias_hash_sources.get(scanned_file_path) or str(
                            family_targets.get(scanned_file_path, {}).get("resolved_path", scanned_file_path)
                        )
                        hash_source_by_path[scanned_file_path] = hash_source
                        if hash_source not in seen_hash_sources:
                            hash_sources.append(hash_source)
                            seen_hash_sources.add(hash_source)
                            with suppress(OSError):
                                hash_budget_bytes += os.path.getsize(hash_source)
                    representative_hash_source = hash_source_by_path.get(representative_file)
                    if not scanner_selection.allows("onnx") or representative_hash_source is None:
                        continue
                    representative_hash_deferred = should_defer_hash_for_file_backed_onnx(
                        representative_hash_source,
                        config,
                    )
                    if representative_hash_deferred:
                        aggregate_hash_complete = False
                    if not _should_defer_hash_for_max_file_size(representative_hash_source, config):
                        representative_external_sources: list[str] = []
                        representative_external_bytes = 0
                        onnx_discovery_path = Path(
                            trusted_hf_alias_logical_paths.get(
                                representative_file,
                                str(logical_local_path(representative_file)),
                            )
                        )
                        discovered_external_data_paths = _streamed_onnx_external_data_hash_paths(
                            onnx_discovery_path,
                            deadline=start_time + timeout,
                        )
                        if discovered_external_data_paths is None:
                            aggregate_hash_complete = False
                        for external_data_path in discovered_external_data_paths or ():
                            external_data_identity = _snapshot_file_identity(external_data_path)
                            external_data_target_key = _file_target_identity_key(
                                external_data_path,
                                external_data_identity,
                            )
                            if (
                                external_data_target_key is not None
                                and external_data_target_key in scan_entry_target_keys
                            ):
                                if external_data_identity is not None:
                                    external_data_source = str(
                                        Path(external_data_identity.resolved_path)
                                        if external_data_identity.resolved_path is not None
                                        else external_data_path
                                    )
                                    onnx_external_data_routing_paths[external_data_source] = str(external_data_path)
                                    representative_external_sources.append(external_data_source)
                                continue
                            if _should_defer_hash_for_max_file_size(str(external_data_path), config):
                                aggregate_hash_complete = False
                                continue
                            if external_data_identity is None:
                                aggregate_hash_complete = False
                                continue
                            external_data_size = _snapshot_file_size(external_data_identity)
                            representative_external_bytes += external_data_size
                            if max_total_size > 0 and hash_budget_bytes + external_data_size > max_total_size:
                                aggregate_hash_complete = False
                                continue
                            external_data_source = str(
                                Path(external_data_identity.resolved_path)
                                if external_data_identity.resolved_path is not None
                                else external_data_path
                            )
                            if external_data_source not in seen_hash_sources:
                                hash_budget_bytes += external_data_size
                                seen_hash_sources.add(external_data_source)
                                if not representative_hash_deferred:
                                    hash_sources.append(external_data_source)
                            onnx_external_data_routing_paths[external_data_source] = str(external_data_path)
                            representative_external_sources.append(external_data_source)
                            if external_data_target_key is not None:
                                scan_entry_target_keys.add(external_data_target_key)
                        if representative_external_sources:
                            onnx_external_data_sources_by_path[representative_file] = representative_external_sources
                        if representative_external_bytes:
                            onnx_external_data_sizes_by_path[representative_file] = representative_external_bytes

                if (
                    directory_owner_class is not None
                    and directory_owner_result is None
                    and owner_block_reason is None
                    and max_total_size > 0
                ):
                    union_sources = list(
                        dict.fromkeys(
                            [*hash_sources, *(owner_content_source(source) for source in owner_budget_sources)]
                        )
                    )
                    try:
                        union_source_bytes = sum(
                            os.stat(source, follow_symlinks=False).st_size for source in union_sources
                        )
                    except OSError as error:
                        owner_block_reason = "directory_owner_snapshot_incomplete"
                        owner_block_details = {"error_type": type(error).__name__}
                    else:
                        if union_source_bytes > max_total_size:
                            owner_block_reason = "directory_owner_max_total_size"
                            owner_block_details = {
                                "max_total_size": max_total_size,
                                "owner_and_child_source_bytes": union_source_bytes,
                            }
                            aggregate_hash_complete = False
                            limit_reached = True
                            scan_entries = []
                            hash_sources.clear()
                            seen_hash_sources.clear()
                            hash_source_by_path.clear()

                top_level_hashing_started_at = _start_phase_timing(phase_timings)
                routing_paths_by_source = {
                    hash_source: scanned_file_path for scanned_file_path, hash_source in hash_source_by_path.items()
                }
                routing_paths_by_source.update(onnx_external_data_routing_paths)
                routing_paths_by_source.update(
                    {
                        owner_source: owner_source
                        for owner_source in directory_owner_source_paths
                        if owner_source not in routing_paths_by_source
                    }
                )
                hashed_identities_by_source: dict[str, dict[str, int]] = {}
                hashes_by_source = _hash_files_by_path(
                    hash_sources,
                    config=config,
                    routing_paths=routing_paths_by_source,
                    follow_symlink_paths=trusted_hf_alias_scan_paths,
                    hashed_identities=hashed_identities_by_source,
                    deadline=start_time + timeout,
                )
                owner_hash_config = dict(config)
                owner_hash_config["max_file_size"] = 0
                owner_hash_config["max_total_size"] = 0

                recorded_content_hashes: set[str] = set()
                if directory_owner_class is not None and directory_owner_result is None:
                    child_owner_relative_parts: set[tuple[str, ...]] = set()
                    child_content_sources: set[str] = set()
                    for child_source in hash_source_by_path.values():
                        try:
                            child_content_source = Path(child_source).resolve(strict=True)
                        except (OSError, RuntimeError):
                            continue
                        child_content_sources.add(str(child_content_source))
                        try:
                            child_owner_relative_parts.add(child_content_source.relative_to(base_dir).parts)
                        except ValueError:
                            continue

                    def owner_source_covered_by_child(source: str) -> bool:
                        if Path(os.path.relpath(source, owner_root_path)).parts in child_owner_relative_parts:
                            return True
                        try:
                            owner_content_path = Path(owner_content_source(source)).resolve(strict=True)
                        except (OSError, RuntimeError):
                            return False
                        return str(owner_content_path) in child_content_sources

                    owner_only_sources = [
                        source for source in owner_sources if not owner_source_covered_by_child(source)
                    ]

                    if owner_block_reason is None:
                        owner_source_by_content_source = {
                            owner_content_source(source): source for source in owner_sources
                        }
                        unhashed_owner_sources = [
                            owner_content_source(source)
                            for source in owner_sources
                            if owner_hash_missing_or_deferred(hashes_by_source, source)
                        ]
                        owner_hash_identities: dict[str, dict[str, int]] = {}
                        hashes_by_source.update(
                            _hash_files_by_path(
                                unhashed_owner_sources,
                                config=owner_hash_config,
                                routing_paths={
                                    source: owner_source_by_content_source.get(source, source)
                                    for source in unhashed_owner_sources
                                },
                                hashed_identities=owner_hash_identities,
                                deadline=start_time + timeout,
                            )
                        )
                        hashed_identities_by_source.update(owner_hash_identities)

                    owner_hashes_before = {
                        source: owner_hash_for_source(hashes_by_source, source) or f"unhashable_{id(source)}"
                        for source in owner_sources
                    }
                    file_backed_hdf5_owner_source_count = sum(
                        _is_file_backed_hdf5_hash_placeholder(hash_value) for hash_value in owner_hashes_before.values()
                    )
                    allow_file_backed_hdf5_owner_hashes = False
                    if owner_block_reason is None:
                        unverifiable_owner_hash_count = sum(
                            _directory_owner_hash_is_unverifiable(
                                hash_value,
                                allow_file_backed_hdf5=True,
                            )
                            for hash_value in owner_hashes_before.values()
                        )
                        if unverifiable_owner_hash_count:
                            owner_block_reason = "directory_owner_snapshot_incomplete"
                            owner_block_details = {"unhashable_source_count": unverifiable_owner_hash_count}
                        elif file_backed_hdf5_owner_source_count:
                            if directory_owner_content_source_paths:
                                owner_block_reason = "directory_owner_snapshot_incomplete"
                                owner_block_details = {
                                    "requires_descriptor_bound_owner": True,
                                    "unhashable_source_count": file_backed_hdf5_owner_source_count,
                                }
                            else:
                                try:
                                    with _bound_directory_owner_scan_path(
                                        owner_root_path,
                                        trusted_root_symlink=bound_local_source_owner_root_trusted,
                                    ):
                                        pass
                                except OSError as error:
                                    owner_block_reason = "directory_owner_snapshot_incomplete"
                                    owner_block_details = {
                                        "error_type": type(error).__name__,
                                        "requires_descriptor_bound_owner": True,
                                        "unhashable_source_count": file_backed_hdf5_owner_source_count,
                                    }
                                else:
                                    allow_file_backed_hdf5_owner_hashes = True

                    owner_snapshot_before_dispatch = directory_owner_initial_snapshot
                    if owner_block_reason is None:
                        try:
                            owner_snapshot_before_dispatch = _capture_directory_owner_namespace(
                                owner_root_path,
                                directory_owner_class,
                                deadline=start_time + timeout,
                                max_entries=directory_owner_snapshot_max_entries,
                                trusted_root_symlink=bound_local_source_owner_root_trusted,
                            )
                        except (OSError, RuntimeError, TimeoutError) as error:
                            owner_block_reason, owner_block_details = directory_owner_snapshot_failure(error)
                        else:
                            changed_owner_relative_parts = _directory_owner_snapshot_changed_paths(
                                directory_owner_initial_snapshot,
                                owner_snapshot_before_dispatch,
                            )
                            if changed_owner_relative_parts:
                                invalidated_owner_relative_parts.update(changed_owner_relative_parts)
                                owner_block_reason = "directory_owner_source_changed"
                                owner_block_details = {"changed_source_count": len(changed_owner_relative_parts)}

                    if invalidated_owner_relative_parts:
                        scan_entries = [
                            entry for entry in scan_entries if not scan_entry_has_invalidated_owner_source(entry)
                        ]
                        hash_source_by_path = {
                            scanned_path: source
                            for scanned_path, source in hash_source_by_path.items()
                            if not owner_scan_path_is_invalidated(scanned_path)
                        }

                    if owner_block_reason is not None:
                        aggregate_hash_complete = False
                        directory_owner_result = ScanResult(scanner_name=directory_owner_class.name)
                        directory_owner_result.add_check(
                            name="Directory Owner Source Snapshot",
                            passed=False,
                            message=(
                                "Logical model-directory analysis was not run because its lexical source "
                                "snapshot was incomplete or unstable"
                            ),
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                **owner_block_details,
                                "analysis_incomplete": True,
                                "scan_outcome_reason": owner_block_reason,
                            },
                        )
                        _mark_inconclusive_scan_outcome(directory_owner_result, owner_block_reason)
                        _mark_operational_scan_error(directory_owner_result, owner_block_reason)
                        directory_owner_result.finish(success=False)
                        merge_directory_owner_result(directory_owner_result, dispatched=False)
                    else:
                        owner_config = dict(config)
                        owner_config["timeout"] = max(1, timeout - int(time.time() - start_time))
                        directory_scan_started_at = time.time()
                        owner_scan_started = False
                        owner_scan_returned = False
                        try:
                            with _directory_owner_scan_path(
                                owner_root_path,
                                owner_snapshot_before_dispatch,
                                owner_hashes_before,
                                config=owner_hash_config,
                                deadline=start_time + timeout,
                                force_staged=bool(directory_owner_content_source_paths),
                                require_bound=allow_file_backed_hdf5_owner_hashes,
                                source_paths_by_owner_path=directory_owner_content_source_paths,
                                trusted_root_symlink=bound_local_source_owner_root_trusted,
                            ) as directory_owner_scan_path:
                                owner_scan_started = True
                                directory_owner_result = directory_owner_class(config=owner_config).scan(
                                    directory_owner_scan_path,
                                )
                        except Exception as error:
                            aggregate_hash_complete = False
                            directory_owner_result = ScanResult(scanner_name=directory_owner_class.name)
                            directory_owner_result.add_check(
                                name="Directory Owner Scan",
                                passed=False,
                                message=(
                                    "Unable to complete logical model-directory analysis: "
                                    f"{_redacted_scan_error_for_reporting(error, path)}"
                                ),
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={
                                    "exception_type": type(error).__name__,
                                    "analysis_incomplete": True,
                                    "scan_outcome_reason": "directory_owner_scan_failed",
                                },
                            )
                            _mark_inconclusive_scan_outcome(directory_owner_result, "directory_owner_scan_failed")
                            _mark_operational_scan_error(directory_owner_result, "directory_owner_scan_failed")
                            directory_owner_result.finish(success=False)
                        else:
                            owner_scan_returned = True
                            if directory_owner_scan_path != path:
                                _normalize_directory_owner_scan_result_for_reporting(
                                    directory_owner_result,
                                    directory_owner_scan_path,
                                    path,
                                )

                        record_scanner_used(
                            directory_owner_class.name,
                            "directory",
                            time.time() - directory_scan_started_at,
                        )
                        post_snapshot_reason: str | None = None
                        post_snapshot_details: dict[str, Any] = {}
                        try:
                            owner_snapshot_after_dispatch = _capture_directory_owner_namespace(
                                owner_root_path,
                                directory_owner_class,
                                deadline=start_time + timeout,
                                max_entries=directory_owner_snapshot_max_entries,
                                trusted_root_symlink=bound_local_source_owner_root_trusted,
                            )
                        except (OSError, RuntimeError, TimeoutError) as error:
                            post_snapshot_reason, post_snapshot_details = directory_owner_snapshot_failure(error)
                        else:
                            changed_owner_relative_parts = _directory_owner_snapshot_changed_paths(
                                directory_owner_initial_snapshot,
                                owner_snapshot_after_dispatch,
                            )
                            if changed_owner_relative_parts:
                                invalidated_owner_relative_parts.update(changed_owner_relative_parts)
                                post_snapshot_reason = "directory_owner_source_changed"
                                post_snapshot_details = {
                                    "changed_source_count": len(changed_owner_relative_parts),
                                }

                        post_owner_identities: dict[str, dict[str, int]] = {}
                        owner_content_sources = [owner_content_source(source) for source in owner_sources]
                        owner_hashes_after_by_content_source = _hash_files_by_path(
                            owner_content_sources,
                            config=owner_hash_config,
                            routing_paths={
                                owner_content_source(source): source
                                for source in owner_sources
                                if owner_content_source(source) in owner_content_sources
                            },
                            hashed_identities=post_owner_identities,
                            deadline=start_time + timeout,
                        )
                        hashes_by_source.update(owner_hashes_after_by_content_source)
                        hashed_identities_by_source.update(post_owner_identities)
                        owner_hashes_after = {
                            source: owner_hashes_after_by_content_source.get(
                                owner_content_source(source),
                                f"unhashable_{id(source)}",
                            )
                            for source in owner_sources
                        }
                        changed_owner_sources = [
                            source
                            for source in owner_sources
                            if _directory_owner_hash_changed(
                                owner_hashes_before.get(source),
                                owner_hashes_after.get(source),
                                allow_file_backed_hdf5=allow_file_backed_hdf5_owner_hashes,
                            )
                        ]
                        if post_snapshot_reason is None and changed_owner_sources:
                            post_snapshot_reason = "directory_owner_source_changed"
                            post_snapshot_details = {"changed_source_count": len(changed_owner_sources)}
                        if post_snapshot_reason is None:
                            unverifiable_owner_hash_count = sum(
                                _directory_owner_hash_is_unverifiable(
                                    hash_value,
                                    allow_file_backed_hdf5=allow_file_backed_hdf5_owner_hashes,
                                )
                                for hash_value in owner_hashes_after.values()
                            )
                            if unverifiable_owner_hash_count:
                                post_snapshot_reason = "directory_owner_snapshot_incomplete"
                                post_snapshot_details = {"unhashable_source_count": unverifiable_owner_hash_count}

                        assert directory_owner_result is not None
                        if post_snapshot_reason is not None:
                            aggregate_hash_complete = False
                            if invalidated_owner_relative_parts:
                                scan_entries = [
                                    entry
                                    for entry in scan_entries
                                    if not scan_entry_has_invalidated_owner_source(entry)
                                ]
                                hash_source_by_path = {
                                    scanned_path: source
                                    for scanned_path, source in hash_source_by_path.items()
                                    if not owner_scan_path_is_invalidated(scanned_path)
                                }
                            directory_owner_result.add_check(
                                name="Directory Owner Source Stability",
                                passed=False,
                                message=(
                                    "Logical model-directory sources could not be proven stable during owner analysis"
                                ),
                                severity=IssueSeverity.INFO,
                                location=path,
                                details={
                                    **post_snapshot_details,
                                    "analysis_incomplete": True,
                                    "scan_outcome_reason": post_snapshot_reason,
                                },
                            )
                            _mark_inconclusive_scan_outcome(directory_owner_result, post_snapshot_reason)
                            _mark_operational_scan_error(directory_owner_result, post_snapshot_reason)
                            directory_owner_result.finish(success=False)
                        elif owner_scan_returned:
                            for owner_source in owner_only_sources:
                                owner_content_hash = owner_hashes_after[owner_source]
                                if owner_content_hash not in recorded_content_hashes:
                                    file_hashes.append(owner_content_hash)
                                    recorded_content_hashes.add(owner_content_hash)
                            results.bytes_scanned += sum(owner_sizes[source] for source in owner_only_sources)
                            results.files_scanned += len(owner_only_sources)
                            processed_files += len(owner_only_sources)
                        merge_directory_owner_result(directory_owner_result, dispatched=owner_scan_started)

                for family_targets in shard_family_targets.values():
                    for validated_target in family_targets.values():
                        resolved_path = validated_target.get("resolved_path")
                        if isinstance(resolved_path, str) and resolved_path in hashed_identities_by_source:
                            validated_target.update(hashed_identities_by_source[resolved_path])
                content_hashes = {
                    scanned_file_path: hashes_by_source.get(
                        hash_source,
                        f"unhashable_{id(scanned_file_path)}",
                    )
                    for scanned_file_path, hash_source in hash_source_by_path.items()
                }
                if any(
                    _is_incomplete_aggregate_hash_placeholder(content_hash) for content_hash in content_hashes.values()
                ):
                    aggregate_hash_complete = False
                for external_data_sources in onnx_external_data_sources_by_path.values():
                    if any(
                        (external_hash := hashes_by_source.get(external_data_source)) is None
                        or external_hash.startswith("unhashable_")
                        for external_data_source in external_data_sources
                    ):
                        aggregate_hash_complete = False
                _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)
                duplicate_paths_by_hash: dict[str, list[str]] = {}
                for file_path, content_hash in content_hashes.items():
                    if not content_hash.startswith("unhashable_"):
                        duplicate_paths_by_hash.setdefault(content_hash, []).append(file_path)
                if len(scan_entries) > 1:
                    pickle_source_snapshot_stack.enter_context(shared_source_sensitive_caches())
                authoritative_directory_index_paths = {
                    os.path.normcase(os.path.normpath(os.path.abspath(index_path)))
                    for target in directory_shard_targets.values()
                    if isinstance((index_path := target.get("authoritative_shard_index_path")), str)
                }
                accounted_standard_targets: set[tuple[object, ...]] = set()

                def stable_target_key(target: Mapping[str, int | str]) -> tuple[object, ...]:
                    return tuple(target.get(field) for field in ("device", "inode", "size", "mtime_ns", "ctime_ns"))

                def record_accounted_standard_source(source: str) -> None:
                    target_values: Mapping[str, int | str] | None = hashed_identities_by_source.get(source)
                    if target_values is None:
                        snapshotted = _snapshot_regular_file_target(source)
                        if snapshotted is None:
                            return
                        target_values = snapshotted
                    accounted_standard_targets.add(stable_target_key(target_values))

                for representative_file, scanned_file_paths, shard_family_key, repository_member in scan_entries:
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
                            file_config = dict(config)
                            file_config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = repository_inventory_context
                            file_config.setdefault(REPOSITORY_SCAN_ROOT_CONFIG_KEY, str(base_dir))
                            repository_current_file = repository_member or _repository_member_path_for_scan(
                                representative_file,
                                base_dir,
                            )
                            if repository_current_file is not None:
                                file_config[REPOSITORY_CURRENT_FILE_CONFIG_KEY] = repository_current_file
                            if shard_family_key is not None:
                                file_config[_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY] = (
                                    _build_shard_family_cache_fingerprint(
                                        shard_family_key,
                                        scanned_file_paths,
                                        content_hashes,
                                        shard_family_targets.get(shard_family_key, {}),
                                    )
                                )
                            logical_representative_path = logical_local_path(representative_file)
                            openvino_owner = _openvino_weights_companion_owner(logical_representative_path)
                            if (
                                openvino_owner is not None
                                and _openvino_xml_companion_key(openvino_owner) in covered_openvino_xml_companions
                            ):
                                file_config = _with_openvino_scanned_xml_companion(file_config, openvino_owner)

                            def pinned_companions(
                                logical_root: str,
                                family_paths: list[str],
                                current_config: dict[str, Any],
                            ) -> tuple[
                                dict[str, tuple[str, dict[str, int | str]]],
                                dict[str, str],
                                tuple[str, int] | None,
                            ]:
                                nonlocal aggregate_hash_complete
                                pinned_targets: dict[str, tuple[str, dict[str, int | str]]] = {}
                                oversized_companion: tuple[str, int] | None = None
                                logical_root_path = trusted_hf_alias_logical_paths.get(logical_root, logical_root)
                                context_only_companions: set[Path] = set()
                                logical_paths_by_source = {
                                    source: onnx_external_data_routing_paths[source]
                                    for source in onnx_external_data_sources_by_path.get(
                                        logical_root,
                                        (),
                                    )
                                    if source in onnx_external_data_routing_paths
                                }
                                if scanner_selection.allows("openvino"):
                                    openvino_companion = _openvino_xml_weights_companion(Path(logical_root_path))
                                    if (
                                        openvino_companion is not None
                                        and _openvino_weights_symlink_escape(
                                            Path(logical_root_path),
                                            openvino_companion,
                                        )
                                        is None
                                    ):
                                        logical_paths_by_source.setdefault(
                                            str(openvino_companion),
                                            str(openvino_companion),
                                        )
                                if scanner_selection.allows("mxnet"):
                                    for mxnet_companion in _mxnet_companion_paths(Path(logical_root_path)):
                                        logical_paths_by_source.setdefault(
                                            str(mxnet_companion),
                                            str(mxnet_companion),
                                        )
                                if scanner_selection.allows("oci_layer"):
                                    context_only_companions.update(
                                        _oci_manifest_layer_companion_paths(Path(logical_root_path))
                                    )
                                    for layer_companion in context_only_companions:
                                        logical_paths_by_source.setdefault(
                                            str(layer_companion),
                                            str(layer_companion),
                                        )
                                for scanned_companion_path in family_paths[1:]:
                                    companion_source = hash_source_by_path.get(scanned_companion_path)
                                    if companion_source is not None:
                                        logical_paths_by_source.setdefault(
                                            companion_source,
                                            scanned_companion_path,
                                        )
                                for companion_source, logical_companion_path in logical_paths_by_source.items():
                                    try:
                                        relative_companion_path = str(
                                            Path(logical_companion_path).relative_to(Path(logical_root_path).parent)
                                        )
                                    except ValueError:
                                        aggregate_hash_complete = False
                                        continue
                                    companion_target = _snapshot_regular_file_target(companion_source)
                                    if companion_target is None:
                                        aggregate_hash_complete = False
                                        continue
                                    hashed_companion_identity = hashed_identities_by_source.get(companion_source)
                                    if hashed_companion_identity is not None:
                                        companion_target.update(hashed_companion_identity)
                                    context_only = Path(logical_companion_path) in context_only_companions
                                    if context_only:
                                        companion_target[CONTEXT_ONLY_COMPANION_TARGET_KEY] = 1
                                    companion_size = companion_target.get("size")
                                    if (
                                        not context_only
                                        and isinstance(companion_size, int)
                                        and _should_defer_hash_for_max_file_size(
                                            logical_companion_path,
                                            current_config,
                                            file_size=companion_size,
                                        )
                                    ):
                                        oversized_companion = (logical_companion_path, companion_size)
                                        continue
                                    resolved_companion_target = os.path.realpath(str(companion_target["resolved_path"]))
                                    companion_target["resolved_path"] = resolved_companion_target
                                    pinned_targets[relative_companion_path] = (
                                        resolved_companion_target,
                                        companion_target,
                                    )
                                return pinned_targets, logical_paths_by_source, oversized_companion

                            def scan_pinned_local_source(
                                resolved_target: str,
                                expected_target: dict[str, int | str],
                                *,
                                logical_path: str,
                                report_path: str,
                                family_paths: list[str],
                                require_regular_path: bool,
                                current_config: dict[str, Any],
                                companion_root: str | None = None,
                            ) -> tuple[ScanResult, dict[str, str]]:
                                """Preflight budgets, scan one retained source, and preserve its logical report path."""
                                nonlocal aggregate_hash_complete, limit_reached
                                logical_companion_root = Path(companion_root or logical_path)
                                escaped_openvino_companion: tuple[Path, Path] | None = None
                                if scanner_selection.allows("openvino"):
                                    openvino_companion = _openvino_xml_weights_companion(logical_companion_root)
                                    if openvino_companion is not None:
                                        resolved_escape = _openvino_weights_symlink_escape(
                                            logical_companion_root,
                                            openvino_companion,
                                        )
                                        if resolved_escape is not None:
                                            escaped_openvino_companion = (
                                                openvino_companion,
                                                resolved_escape,
                                            )
                                source_size = expected_target.get("size")
                                if not isinstance(source_size, int):
                                    aggregate_hash_complete = False
                                    return _local_source_boundary_failure_scan_result(report_path), {}
                                if _should_defer_hash_for_max_file_size(
                                    logical_path,
                                    current_config,
                                    file_size=source_size,
                                ):
                                    aggregate_hash_complete = False
                                    return (
                                        _max_file_size_failure_scan_result(report_path, source_size, max_file_size),
                                        {},
                                    )

                                companion_targets, companion_paths_by_source, oversized_companion = pinned_companions(
                                    companion_root or logical_path,
                                    family_paths,
                                    current_config,
                                )
                                if oversized_companion is not None:
                                    aggregate_hash_complete = False
                                    companion_path, companion_size = oversized_companion
                                    return (
                                        _max_file_size_failure_scan_result(
                                            companion_path,
                                            companion_size,
                                            max_file_size,
                                        ),
                                        companion_paths_by_source,
                                    )

                                staged_targets = [expected_target]
                                staged_targets.extend(target for _path, target in companion_targets.values())
                                unique_staged_targets: dict[tuple[object, ...], int] = {}
                                for staged_target in staged_targets:
                                    staged_size = staged_target.get("size")
                                    if not isinstance(staged_size, int):
                                        aggregate_hash_complete = False
                                        return _local_source_boundary_failure_scan_result(report_path), {}
                                    if staged_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY):
                                        continue
                                    target_key = stable_target_key(staged_target)
                                    unique_staged_targets.setdefault(target_key, staged_size)
                                projected_total = results.bytes_scanned + sum(
                                    staged_size
                                    for target_key, staged_size in unique_staged_targets.items()
                                    if target_key not in accounted_standard_targets
                                )
                                if max_total_size > 0 and projected_total > max_total_size:
                                    aggregate_hash_complete = False
                                    limit_reached = True
                                    return (
                                        _max_total_size_failure_scan_result(
                                            report_path,
                                            projected_total,
                                            max_total_size,
                                        ),
                                        companion_paths_by_source,
                                    )

                                try:
                                    with _pinned_shard_scan_path(
                                        resolved_target,
                                        expected_target,
                                        logical_path=logical_path,
                                        companion_targets=companion_targets,
                                        require_regular_path=require_regular_path or bool(companion_targets),
                                        copy_max_bytes=sum(
                                            staged_size
                                            for staged_target in staged_targets
                                            if not staged_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY)
                                            if isinstance((staged_size := staged_target.get("size")), int)
                                        ),
                                        deadline=start_time + timeout,
                                    ) as pinned_source_scan:
                                        with _trusted_logical_scan_path(pinned_source_scan.path, logical_path):
                                            local_result = scan_file(pinned_source_scan.path, current_config)
                                        _rebase_pinned_shard_result(
                                            local_result,
                                            pinned_source_scan.path,
                                            report_path,
                                        )
                                        _rebase_pinned_shard_result(
                                            local_result,
                                            str(Path(pinned_source_scan.path).parent),
                                            str(Path(report_path).parent),
                                        )
                                        pinned_source_parent = os.path.realpath(Path(pinned_source_scan.path).parent)
                                        _rebase_pinned_shard_result(
                                            local_result,
                                            pinned_source_parent,
                                            str(Path(report_path).parent),
                                        )
                                    if pinned_source_scan.changed_during_scan:
                                        aggregate_hash_complete = False
                                        local_result.merge(_local_source_boundary_failure_scan_result(report_path))
                                except (_ShardPinUnavailableError, OSError) as error:
                                    aggregate_hash_complete = False
                                    local_result = _local_source_boundary_failure_scan_result(report_path, error)
                                if escaped_openvino_companion is not None:
                                    escaped_companion_path, escaped_companion_target = escaped_openvino_companion
                                    local_result.metadata.pop("bin_size", None)
                                    local_result.merge(
                                        _openvino_weights_symlink_escape_result(
                                            logical_companion_root,
                                            escaped_companion_path,
                                            escaped_companion_target,
                                        )
                                    )
                                return local_result, companion_paths_by_source

                            trusted_alias_target = (
                                trusted_hf_alias_targets.get(representative_file)
                                if shard_family_key is None and representative_file in trusted_hf_alias_scan_paths
                                else None
                            )
                            if shard_family_key is None and representative_file in trusted_hf_alias_scan_paths:
                                if trusted_alias_target is None:
                                    aggregate_hash_complete = False
                                    file_result = _local_source_boundary_failure_scan_result(representative_file)
                                else:
                                    expected_alias_target = dict(trusted_alias_target)
                                    alias_hash_source = hash_source_by_path.get(representative_file)
                                    hashed_alias_identity = (
                                        hashed_identities_by_source.get(alias_hash_source)
                                        if alias_hash_source is not None
                                        else None
                                    )
                                    if hashed_alias_identity is not None:
                                        expected_alias_target.update(hashed_alias_identity)
                                    resolved_alias_target = expected_alias_target.get("resolved_path")
                                    if not isinstance(resolved_alias_target, str):
                                        aggregate_hash_complete = False
                                        file_result = _local_source_boundary_failure_scan_result(representative_file)
                                    else:
                                        file_config["cache_enabled"] = False
                                        file_result, _companion_paths_by_source = scan_pinned_local_source(
                                            resolved_alias_target,
                                            expected_alias_target,
                                            logical_path=trusted_hf_alias_logical_paths.get(
                                                representative_file, representative_file
                                            ),
                                            report_path=representative_file,
                                            family_paths=scanned_file_paths,
                                            require_regular_path=False,
                                            current_config=file_config,
                                            companion_root=representative_file,
                                        )
                            elif (
                                shard_family_key is None
                                and os.path.normcase(
                                    os.path.normpath(
                                        os.path.abspath(
                                            _local_source_logical_path(
                                                representative_file,
                                                bound_local_source_path,
                                                resolved_local_source_path,
                                            )
                                        )
                                    )
                                )
                                not in authoritative_directory_index_paths
                            ):
                                source_path = hash_source_by_path.get(representative_file, representative_file)
                                expected_source_target = _snapshot_regular_file_target(source_path)
                                hashed_source_identity = hashed_identities_by_source.get(source_path)
                                if expected_source_target is not None and hashed_source_identity is not None:
                                    expected_source_target.update(hashed_source_identity)
                                resolved_source_target = (
                                    expected_source_target.get("resolved_path")
                                    if expected_source_target is not None
                                    else None
                                )
                                if not isinstance(resolved_source_target, str):
                                    aggregate_hash_complete = False
                                    file_result = _local_source_boundary_failure_scan_result(representative_file)
                                else:
                                    assert expected_source_target is not None
                                    resolved_source_target = os.path.realpath(resolved_source_target)
                                    expected_source_target["resolved_path"] = resolved_source_target
                                    file_config["cache_enabled"] = False
                                    file_result, _companion_paths_by_source = scan_pinned_local_source(
                                        resolved_source_target,
                                        expected_source_target,
                                        logical_path=representative_file,
                                        report_path=representative_file,
                                        family_paths=scanned_file_paths,
                                        require_regular_path=True,
                                        current_config=file_config,
                                        companion_root=str(logical_representative_path),
                                    )
                            else:
                                file_result = scan_file(representative_file, file_config)
                            if file_result.scanner_name != "size_check":
                                file_result.bytes_scanned += covered_openvino_companion_sizes.get(
                                    _openvino_xml_companion_key(logical_representative_path),
                                    0,
                                )
                                file_result.bytes_scanned += onnx_external_data_sizes_by_path.get(
                                    representative_file,
                                    0,
                                )
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
                            record_accounted_standard_source(
                                hash_source_by_path.get(scanned_file_path, scanned_file_path)
                            )
                        for external_data_source in onnx_external_data_sources_by_path.get(
                            representative_file,
                            (),
                        ):
                            record_accounted_standard_source(external_data_source)
                        openvino_companion = _openvino_xml_weights_companion(logical_representative_path)
                        if openvino_companion is not None:
                            record_accounted_standard_source(str(openvino_companion))
                        for scanned_file_path in scanned_file_paths:
                            path_content_hash = content_hashes.get(scanned_file_path)
                            if (
                                path_content_hash is not None
                                and not path_content_hash.startswith("unhashable_")
                                and path_content_hash not in recorded_content_hashes
                            ):
                                file_hashes.append(path_content_hash)
                                recorded_content_hashes.add(path_content_hash)
                        for onnx_external_data_source in onnx_external_data_sources_by_path.get(
                            representative_file,
                            (),
                        ):
                            external_data_content_hash = hashes_by_source.get(onnx_external_data_source)
                            if (
                                external_data_content_hash is not None
                                and not external_data_content_hash.startswith("unhashable_")
                                and external_data_content_hash not in recorded_content_hashes
                            ):
                                file_hashes.append(external_data_content_hash)
                                recorded_content_hashes.add(external_data_content_hash)

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

                        if limit_reached:
                            break
                        if max_total_size > 0 and results.bytes_scanned > max_total_size:
                            aggregate_hash_complete = False
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
                        scan_metadata["has_operational_errors"] = True

                        _add_issue_to_model(
                            results,
                            f"Error scanning file: {e!s}",
                            severity=IssueSeverity.INFO.value,
                            location=representative_file,
                            details={"exception_type": type(e).__name__},
                        )
                        for scanned_file_path in scanned_file_paths:
                            _add_error_asset_to_results(results, scanned_file_path)

            actual_dvc_covered_paths: set[str] = set()
            if pending_dvc_output_limit_checks:
                from modelaudit.scanners import get_scanner_for_file

                for asset in results.assets:
                    if asset.type == "error" or not os.path.isfile(asset.path):
                        continue
                    metadata = results.file_metadata.get(asset.path)
                    if metadata is not None and (
                        metadata.get("operational_error") is True or _metadata_has_incomplete_coverage(metadata)
                    ):
                        continue
                    if _records_have_incomplete_coverage_for_path(
                        results.checks,
                        asset.path,
                        allow_skipped_check_exemption=True,
                    ) or _records_have_incomplete_coverage_for_path(results.issues, asset.path):
                        continue
                    if scanner_selection.active and get_scanner_for_file(asset.path, config=config) is None:
                        continue
                    actual_dvc_covered_paths.add(str(Path(asset.path).resolve()))

                for dvc_path, dvc_resolution in pending_dvc_output_limit_checks:
                    if not _dvc_omitted_outputs_covered_by_directory_walk(
                        dvc_path,
                        dvc_resolution,
                        actual_dvc_covered_paths,
                        directory_walk_covered_directories,
                        skip_file_types=skip_file_types,
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_extensions,
                    ):
                        aggregate_hash_complete = False
                        _record_dvc_output_limit_incomplete(results, scan_metadata, dvc_path, dvc_resolution)

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
            for guard_fd, guarded_path, guarded_target in windows_shard_guards:
                if _windows_shard_guard_is_stable(guard_fd, guarded_target):
                    continue
                aggregate_hash_complete = False
                scan_metadata["success"] = False
                scan_metadata["has_operational_errors"] = True
                results.checks.append(
                    Check(
                        name="Sharded Model Boundary Check",
                        status=CheckStatus.FAILED,
                        message="Validated directory shard changed before terminal reconciliation.",
                        severity=IssueSeverity.INFO,
                        location=guarded_path,
                        details={
                            "path": guarded_path,
                            "reason": "shard_target_changed_after_scan",
                            "analysis_incomplete": True,
                            "operational_error": True,
                            "scan_outcome": "inconclusive",
                            "scan_outcome_reason": "shard_boundary_changed",
                        },
                    )
                )
            directory_boundary_failures = _terminal_safetensors_shard_boundary_failures(
                directory_shard_targets,
                index_search_root=base_dir,
                index_inspection_context=index_inspection_context,
            )
            for failed_path, failure_reason in directory_boundary_failures.items():
                if any(
                    check.name == "Sharded Model Boundary Check"
                    and check.location == failed_path
                    and check.details.get("reason") == failure_reason
                    for check in results.checks
                ):
                    continue
                aggregate_hash_complete = False
                scan_metadata["success"] = False
                scan_metadata["has_operational_errors"] = True
                results.checks.append(
                    Check(
                        name="Sharded Model Boundary Check",
                        status=CheckStatus.FAILED,
                        message="Validated directory shard authority changed after scanning.",
                        severity=IssueSeverity.INFO,
                        location=failed_path,
                        details={
                            "path": failed_path,
                            "reason": failure_reason,
                            "analysis_incomplete": True,
                            "operational_error": True,
                            "scan_outcome": "inconclusive",
                            "scan_outcome_reason": "shard_boundary_changed",
                        },
                    )
                )
        else:
            # Scan a single file or DVC pointer
            target_files = [path]
            single_dvc_resolution: DvcResolution | None = None
            dvc_scanned_directories: set[str] = set(dvc_external_covered_directories)
            internally_scanned_dvc_directories: set[str] = set()
            is_dvc_pointer = path.lower().endswith(".dvc")
            if is_dvc_pointer:
                dvc_resolution = resolve_dvc_file_status(path)
                single_dvc_resolution = dvc_resolution
                if dvc_resolution.has_non_cap_gap:
                    _record_incomplete_dvc_resolution(results, scan_metadata, path, dvc_resolution)
                    aggregate_hash_complete = False
                target_files = list(single_dvc_resolution.resolved_paths)
            dvc_declared_output_roots = tuple(str(Path(target).resolve()) for target in target_files)
            scanned_dvc_paths: set[str] = set(dvc_external_covered_paths)
            internally_scanned_dvc_paths: set[str] = set()

            for _idx, target in enumerate(target_files):
                # Check for interrupts
                check_interrupted()

                resolved_target = str(Path(target).resolve())
                if is_dvc_pointer and resolved_target in scanned_dvc_paths:
                    if resolved_target in dvc_external_covered_paths:
                        aggregate_hash_complete = False
                    continue

                target_timeout = timeout
                target_max_total_size = max_total_size
                target_config = config
                if is_dvc_pointer:
                    target_timeout = timeout - int(time.time() - start_time)
                    if target_timeout <= 0:
                        aggregate_hash_complete = False
                        _record_incomplete_dvc_scan_budget(
                            results,
                            scan_metadata,
                            path,
                            budget_type="timeout",
                            limit=timeout,
                        )
                        break

                    if max_total_size > 0:
                        target_max_total_size = max_total_size - results.bytes_scanned
                        can_probe_zero_byte_target = False
                        if target_max_total_size == 0:
                            if os.path.isdir(target):
                                # The nested directory scan applies the exact zero-byte
                                # budget to its filtered scan entries before hashing.
                                can_probe_zero_byte_target = True
                            elif os.path.isfile(target):
                                try:
                                    can_probe_zero_byte_target = os.path.getsize(target) == 0
                                except OSError:
                                    can_probe_zero_byte_target = False
                        if target_max_total_size < 0 or (target_max_total_size == 0 and not can_probe_zero_byte_target):
                            aggregate_hash_complete = False
                            _record_incomplete_dvc_scan_budget(
                                results,
                                scan_metadata,
                                path,
                                budget_type="total_size",
                                limit=max_total_size,
                            )
                            break
                        if can_probe_zero_byte_target:
                            # A zero max means unlimited to nested scanners. Allow a
                            # one-byte bounded probe and verify the parent total below.
                            target_max_total_size = 1

                    target_config = dict(config)
                    target_config["timeout"] = target_timeout
                    target_config["max_total_size"] = target_max_total_size

                if os.path.isdir(target):
                    nested_kwargs = dict(kwargs)
                    if is_dvc_pointer:
                        nested_kwargs[_DVC_PARENT_FILE_CONFIG_KEY] = path
                        nested_kwargs[_DVC_EXCLUDED_PATHS_CONFIG_KEY] = tuple(scanned_dvc_paths)
                        nested_kwargs[_DVC_COVERAGE_ROOTS_CONFIG_KEY] = dvc_declared_output_roots
                    if is_dvc_pointer and max_total_size > 0:
                        nested_kwargs[_DVC_REMAINING_TOTAL_SIZE_CONFIG_KEY] = max_total_size - results.bytes_scanned
                        nested_kwargs[_DVC_TOTAL_SIZE_LIMIT_CONFIG_KEY] = max_total_size
                    nested_result = scan_model_directory_or_file(
                        target,
                        blacklist_patterns=blacklist_patterns,
                        timeout=target_timeout,
                        max_file_size=max_file_size,
                        max_total_size=target_max_total_size,
                        strict_license=strict_license,
                        progress_callback=progress_callback,
                        skip_file_types=skip_file_types,
                        **nested_kwargs,
                    )
                    results.aggregate_scan_result(nested_result)
                    nested_scanned_paths = {
                        str(Path(asset.path).resolve())
                        for asset in nested_result.assets
                        if asset.path
                        and asset.type != "error"
                        and not (
                            (metadata := nested_result.file_metadata.get(asset.path)) is not None
                            and (
                                metadata.get("operational_error") is True or _metadata_has_incomplete_coverage(metadata)
                            )
                        )
                        and not (
                            _records_have_incomplete_coverage_for_path(
                                nested_result.checks,
                                asset.path,
                                allow_skipped_check_exemption=True,
                            )
                            or _records_have_incomplete_coverage_for_path(nested_result.issues, asset.path)
                        )
                    }
                    scanned_dvc_paths.update(nested_scanned_paths)
                    internally_scanned_dvc_paths.update(nested_scanned_paths)
                    for root, _dirs, _files in os.walk(target, followlinks=False):
                        resolved_directory = str(Path(root).resolve())
                        if _results_have_incomplete_coverage_under_directory(nested_result, resolved_directory):
                            continue
                        dvc_scanned_directories.add(resolved_directory)
                        internally_scanned_dvc_directories.add(resolved_directory)
                    if nested_result.has_errors or (
                        nested_result.files_scanned > 0 and nested_result.content_hash is None
                    ):
                        aggregate_hash_complete = False
                    for nested_metadata in nested_result.file_metadata.values():
                        nested_content_hash = nested_metadata.get("content_hash")
                        if (
                            isinstance(nested_content_hash, str)
                            and nested_content_hash
                            and nested_content_hash not in file_hashes
                        ):
                            file_hashes.append(nested_content_hash)
                    if nested_result.has_errors:
                        scan_metadata["has_operational_errors"] = True
                    if is_dvc_pointer and max_total_size > 0 and results.bytes_scanned > max_total_size:
                        _record_incomplete_dvc_scan_budget(
                            results,
                            scan_metadata,
                            path,
                            budget_type="total_size",
                            limit=max_total_size,
                        )
                        break
                    if is_dvc_pointer and time.time() - start_time > timeout:
                        aggregate_hash_complete = False
                        _record_incomplete_dvc_scan_budget(
                            results,
                            scan_metadata,
                            path,
                            budget_type="timeout",
                            limit=timeout,
                        )
                        break
                    continue

                if is_dvc_pointer and max_total_size > 0:
                    try:
                        target_size = os.path.getsize(target)
                    except OSError:
                        target_size = 0
                    if target_size > target_max_total_size:
                        aggregate_hash_complete = False
                        _record_incomplete_dvc_scan_budget(
                            results,
                            scan_metadata,
                            path,
                            budget_type="total_size",
                            limit=max_total_size,
                        )
                        break

                if progress_callback:
                    progress_callback(f"Scanning file: {target}", 0.0)

                if os.path.isdir(target):
                    nested_result = scan_model_directory_or_file(target, **config)
                    results.aggregate_scan_result(nested_result)
                    for asset in nested_result.assets:
                        asset_path = Path(asset.path)
                        if not asset_path.is_file():
                            continue
                        metadata = nested_result.file_metadata.get(asset.path)
                        if metadata is not None and (
                            metadata.get("operational_error") is True or _metadata_has_incomplete_coverage(metadata)
                        ):
                            continue
                        if _records_have_incomplete_coverage_for_path(
                            nested_result.checks,
                            asset.path,
                            allow_skipped_check_exemption=True,
                        ) or _records_have_incomplete_coverage_for_path(nested_result.issues, asset.path):
                            continue
                        resolved_asset_path = str(asset_path.resolve())
                        scanned_dvc_paths.add(resolved_asset_path)
                        internally_scanned_dvc_paths.add(resolved_asset_path)
                    for root, _dirs, _files in os.walk(target, followlinks=False):
                        resolved_directory = str(Path(root).resolve())
                        if _results_have_incomplete_coverage_under_directory(nested_result, resolved_directory):
                            continue
                        dvc_scanned_directories.add(resolved_directory)
                        internally_scanned_dvc_directories.add(resolved_directory)
                    if _results_have_operational_error(nested_result):
                        scan_metadata["success"] = False
                        scan_metadata["has_operational_errors"] = True
                    results.content_hash = None
                    aggregate_hash_complete = False
                    continue

                single_file_pin_target: dict[str, int | str] | None = None
                single_file_pin_resolved_path: str | None = None
                single_file_companion_targets: dict[str, tuple[str, dict[str, int | str]]] = {}
                single_file_companion_sizes = 0
                single_file_has_symlink_companion = False
                single_file_preflight_result: ScanResult | None = None
                single_file_logical_path = Path(target)
                if (
                    local_source_bound_guard is not None
                    and target == bound_local_source_path
                    and expected_local_source_receipt is not None
                    and expected_local_source_receipt.get("mode_type") == stat.S_IFREG
                    and resolved_local_source_path is not None
                ):
                    single_file_logical_path = Path(local_source_report_path)
                    single_file_pin_target = _snapshot_regular_file_target(resolved_local_source_path)
                    candidate_single_file_pin_resolved_path = (
                        single_file_pin_target.get("resolved_path") if single_file_pin_target is not None else None
                    )
                    single_file_pin_resolved_path = (
                        candidate_single_file_pin_resolved_path
                        if isinstance(candidate_single_file_pin_resolved_path, str)
                        else None
                    )
                    source_size = single_file_pin_target.get("size") if single_file_pin_target is not None else None
                    if not isinstance(single_file_pin_resolved_path, str) or not isinstance(source_size, int):
                        single_file_preflight_result = _local_source_boundary_failure_scan_result(
                            local_source_report_path
                        )
                    elif _should_defer_hash_for_max_file_size(
                        str(single_file_logical_path),
                        target_config,
                        file_size=source_size,
                    ):
                        single_file_preflight_result = _max_file_size_failure_scan_result(
                            local_source_report_path,
                            source_size,
                            max_file_size,
                        )
                    else:
                        companion_paths: list[Path] = []
                        oci_layer_companions: tuple[Path, ...] = ()
                        if not scanner_selection.active or scanner_selection.allows("openvino"):
                            openvino_companion = _openvino_xml_weights_companion(single_file_logical_path)
                            if openvino_companion is not None:
                                companion_paths.append(openvino_companion)
                        if not scanner_selection.active or scanner_selection.allows("onnx"):
                            discovered_onnx_companions = _streamed_onnx_external_data_hash_paths(
                                single_file_logical_path,
                                deadline=start_time + timeout,
                            )
                            if discovered_onnx_companions is None:
                                single_file_preflight_result = _local_source_boundary_failure_scan_result(
                                    local_source_report_path
                                )
                            else:
                                companion_paths.extend(discovered_onnx_companions)
                        if not scanner_selection.active or scanner_selection.allows("mxnet"):
                            companion_paths.extend(_mxnet_companion_paths(single_file_logical_path))
                        if not scanner_selection.active or scanner_selection.allows("oci_layer"):
                            oci_layer_companions = _oci_manifest_layer_companion_paths(single_file_logical_path)
                            companion_paths.extend(oci_layer_companions)
                        for companion_path in dict.fromkeys(companion_paths):
                            try:
                                relative_companion = companion_path.relative_to(single_file_logical_path.parent)
                                resolved_companion = companion_path.resolve(strict=True)
                            except (OSError, RuntimeError, ValueError):
                                single_file_preflight_result = _local_source_boundary_failure_scan_result(
                                    local_source_report_path
                                )
                                break
                            single_file_has_symlink_companion = (
                                single_file_has_symlink_companion or companion_path.is_symlink()
                            )
                            companion_target = _snapshot_regular_file_target(resolved_companion)
                            companion_size = companion_target.get("size") if companion_target is not None else None
                            if not isinstance(companion_size, int):
                                single_file_preflight_result = _local_source_boundary_failure_scan_result(
                                    local_source_report_path
                                )
                                break
                            context_only = companion_path in oci_layer_companions
                            if context_only:
                                assert companion_target is not None
                                companion_target[CONTEXT_ONLY_COMPANION_TARGET_KEY] = 1
                            if not context_only and _should_defer_hash_for_max_file_size(
                                str(companion_path),
                                target_config,
                                file_size=companion_size,
                            ):
                                single_file_preflight_result = _max_file_size_failure_scan_result(
                                    str(companion_path),
                                    companion_size,
                                    max_file_size,
                                )
                                break
                            assert companion_target is not None
                            single_file_companion_targets[str(relative_companion)] = (
                                str(resolved_companion),
                                companion_target,
                            )
                            if not context_only:
                                single_file_companion_sizes += companion_size
                        if os.name == "nt" and single_file_has_symlink_companion:
                            single_file_preflight_result = _local_source_boundary_failure_scan_result(
                                local_source_report_path
                            )
                        projected_size = source_size + single_file_companion_sizes
                        if (
                            single_file_preflight_result is None
                            and max_total_size > 0
                            and projected_size > max_total_size
                        ):
                            single_file_preflight_result = _max_total_size_failure_scan_result(
                                local_source_report_path,
                                projected_size,
                                max_total_size,
                            )

                if single_file_preflight_result is not None:
                    aggregate_hash_complete = False

                results.files_scanned += 1

                # Hash the top-level target before scanning. Archive scanners merge
                # nested member results into their metadata, so scanner-emitted
                # hashes are not always the bytes of this target.
                defer_hash_for_max_total_size = _should_defer_hash_for_max_total_size(
                    config,
                    hashed_bytes=top_level_hashed_bytes,
                )
                defer_hash_for_max_file_size = _should_defer_hash_for_max_file_size(target, config)
                defer_hash_for_file_backed_hdf5 = _should_defer_hash_for_file_backed_hdf5(target)
                defer_hash_for_file_backed_onnx = should_defer_hash_for_file_backed_onnx(target, config)
                defer_hash_for_pytorch_read_limit = should_defer_hash_for_pytorch_read_limit(
                    target,
                    config,
                )
                if (
                    defer_hash_for_max_total_size
                    or defer_hash_for_max_file_size
                    or defer_hash_for_file_backed_hdf5
                    or defer_hash_for_file_backed_onnx
                    or defer_hash_for_pytorch_read_limit
                ):
                    aggregate_hash_complete = False
                if defer_hash_for_pytorch_read_limit:
                    target_config = dict(target_config)
                    target_config["cache_enabled"] = False
                if (
                    not _should_defer_hash_for_safetensors_header_limit(target, config)
                    and not defer_hash_for_max_file_size
                    and not defer_hash_for_max_total_size
                    and not defer_hash_for_file_backed_hdf5
                    and not defer_hash_for_file_backed_onnx
                    and not defer_hash_for_pytorch_read_limit
                ):
                    try:
                        top_level_hashing_started_at = _start_phase_timing(phase_timings)
                        with suppress(OSError):
                            top_level_hashed_bytes += os.path.getsize(target)
                        file_hash = _calculate_file_hash(
                            target,
                            follow_validated_symlink=bool(
                                local_source_bound_guard is not None
                                and local_source_bound_guard.staging_fd is not None
                                and target == bound_local_source_path
                            ),
                        )
                        if not is_dvc_pointer or file_hash not in file_hashes:
                            file_hashes.append(file_hash)
                    except Exception as e:
                        logger.debug(f"Failed to hash file {target}: {e}")
                    finally:
                        _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)

                file_scan_started_at = _start_phase_timing(phase_timings)
                try:
                    if single_file_preflight_result is not None:
                        file_result = single_file_preflight_result
                    elif (
                        single_file_pin_target is not None
                        and single_file_pin_resolved_path is not None
                        and single_file_companion_targets
                    ):
                        single_file_copy_bytes = single_file_pin_target.get("size")
                        assert isinstance(single_file_copy_bytes, int)
                        single_file_copy_bytes += single_file_companion_sizes
                        with _pinned_shard_scan_path(
                            single_file_pin_resolved_path,
                            single_file_pin_target,
                            logical_path=str(single_file_logical_path),
                            companion_targets=single_file_companion_targets,
                            require_regular_path=not single_file_has_symlink_companion,
                            copy_max_bytes=single_file_copy_bytes,
                            deadline=start_time + timeout,
                        ) as pinned_single_file:
                            for relative_name, (
                                _source_path,
                                companion_target,
                            ) in single_file_companion_targets.items():
                                if companion_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY):
                                    continue
                                pinned_companion_path = Path(pinned_single_file.path).parent.joinpath(
                                    *Path(relative_name).parts
                                )
                                try:
                                    companion_hash = _calculate_file_hash(
                                        str(pinned_companion_path),
                                        deadline=start_time + timeout,
                                        follow_validated_symlink=True,
                                    )
                                except Exception as error:
                                    logger.debug(f"Failed to hash companion file {pinned_companion_path}: {error}")
                                    aggregate_hash_complete = False
                                else:
                                    if companion_hash not in file_hashes:
                                        file_hashes.append(companion_hash)
                                    companion_size = companion_target.get("size")
                                    if isinstance(companion_size, int):
                                        top_level_hashed_bytes += companion_size
                            with _trusted_logical_scan_path(
                                pinned_single_file.path,
                                str(single_file_logical_path),
                            ):
                                file_result = scan_file(pinned_single_file.path, target_config)
                            _rebase_pinned_shard_result(file_result, pinned_single_file.path, target)
                            _rebase_pinned_shard_result(
                                file_result,
                                str(Path(pinned_single_file.path).parent),
                                str(single_file_logical_path.parent),
                            )
                            _rebase_pinned_shard_result(
                                file_result,
                                os.path.realpath(Path(pinned_single_file.path).parent),
                                str(single_file_logical_path.parent),
                            )
                        if pinned_single_file.changed_during_scan:
                            file_result.merge(_local_source_boundary_failure_scan_result(local_source_report_path))
                    else:
                        with _trusted_logical_scan_path(target, str(single_file_logical_path)):
                            file_result = scan_file(target, target_config)
                    if single_file_preflight_result is None:
                        file_result.bytes_scanned += single_file_companion_sizes
                finally:
                    _finish_phase_timing(phase_timings, "file_scan_dispatch", file_scan_started_at)

                # Use helper function to add scan result to Pydantic model
                result_merge_started_at = _start_phase_timing(phase_timings)
                _add_scan_result_to_model(results, scan_metadata, file_result, target)

                _add_asset_to_results(results, target, file_result)
                if (
                    is_dvc_pointer
                    and not _scan_result_has_operational_error(file_result)
                    and not _metadata_has_incomplete_coverage(file_result.metadata or {})
                ):
                    target_has_incomplete_record = _records_have_incomplete_coverage_for_path(
                        file_result.checks,
                        target,
                        allow_skipped_check_exemption=True,
                    ) or _records_have_incomplete_coverage_for_path(file_result.issues, target)
                    if not target_has_incomplete_record:
                        scanned_dvc_paths.add(resolved_target)
                        internally_scanned_dvc_paths.add(resolved_target)
                    sharded_detection_families: list[set[str]] = []
                    for check in file_result.checks:
                        shard_paths = check.details.get("shards") if isinstance(check.details, dict) else None
                        if check.name == "Sharded Model Detection" and isinstance(shard_paths, list):
                            sharded_detection_families.append(
                                {
                                    resolved_shard_path
                                    for shard_path in shard_paths
                                    if isinstance(shard_path, str)
                                    and (resolved_shard_path := _resolve_discovered_shard_path(shard_path, results))
                                    is not None
                                }
                            )
                    only_detected_shard_family = len(sharded_detection_families) <= 1
                    for resolved_shard_paths in sharded_detection_families:
                        if _shard_family_has_incomplete_coverage(
                            file_result.checks,
                            resolved_shard_paths,
                            only_detected_shard_family=only_detected_shard_family,
                            allow_skipped_check_exemption=True,
                        ) or _shard_family_has_incomplete_coverage(
                            file_result.issues,
                            resolved_shard_paths,
                            only_detected_shard_family=only_detected_shard_family,
                        ):
                            continue
                        scanned_dvc_paths.update(resolved_shard_paths)
                        internally_scanned_dvc_paths.update(resolved_shard_paths)
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
                    aggregate_hash_complete = False
                    _add_issue_to_model(
                        results,
                        f"Total scan size limit exceeded: {results.bytes_scanned} bytes (max: {max_total_size})",
                        severity=IssueSeverity.INFO.value,
                        location=target,
                        details={"max_total_size": max_total_size, "analysis_incomplete": True},
                    )
                    if is_dvc_pointer:
                        _record_incomplete_dvc_scan_budget(
                            results,
                            scan_metadata,
                            path,
                            budget_type="total_size",
                            limit=max_total_size,
                        )
                    else:
                        scan_metadata["success"] = False
                        scan_metadata["has_operational_errors"] = True
                    break

                if is_dvc_pointer and time.time() - start_time > timeout:
                    aggregate_hash_complete = False
                    _record_incomplete_dvc_scan_budget(
                        results,
                        scan_metadata,
                        path,
                        budget_type="timeout",
                        limit=timeout,
                    )
                    break

                if progress_callback:
                    progress_callback(f"Completed scanning: {target}", 100.0)

            if single_dvc_resolution is not None and single_dvc_resolution.omitted_output_count > 0:
                internally_covered = _dvc_omitted_outputs_covered_by_directory_walk(
                    path,
                    single_dvc_resolution,
                    internally_scanned_dvc_paths,
                    internally_scanned_dvc_directories,
                    skip_file_types=skip_file_types,
                    metadata_scanner_available=metadata_scanner_available,
                    scanner_selection_extensions=scanner_selection_extensions,
                )
                dvc_outputs_covered = internally_covered
                if not internally_covered:
                    dvc_outputs_covered = _dvc_omitted_outputs_covered_by_directory_walk(
                        path,
                        single_dvc_resolution,
                        scanned_dvc_paths,
                        dvc_scanned_directories,
                        skip_file_types=skip_file_types,
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_extensions,
                    )
                    if dvc_outputs_covered:
                        aggregate_hash_complete = False
                if not dvc_outputs_covered:
                    aggregate_hash_complete = False
                    _record_dvc_output_limit_incomplete(results, scan_metadata, path, single_dvc_resolution)

        if local_source_initial_namespace is not None:
            try:
                terminal_local_source_namespace = _capture_directory_owner_namespace(
                    Path(path),
                    None,
                    deadline=start_time + timeout,
                    max_entries=local_source_namespace_max_entries,
                    trusted_root_symlink=bound_local_source_path is not None,
                )
            except (OSError, RuntimeError, TimeoutError) as error:
                raise _LocalSourceBoundaryError("local source namespace changed after scanning") from error
            if _directory_owner_snapshot_changed_paths(
                local_source_initial_namespace,
                terminal_local_source_namespace,
            ):
                raise _LocalSourceBoundaryError("local source namespace changed during scanning")
        if local_source_bound_guard is not None and local_source_bound_guard.changed():
            raise _LocalSourceBoundaryError("retained local source changed during scanning")
        if (
            local_source_bound_guard is None
            and expected_local_source_receipt is not None
            and not _local_source_receipts_match(
                expected_local_source_receipt,
                _snapshot_local_source_receipt(local_source_report_path),
            )
        ):
            raise _LocalSourceBoundaryError("local source changed during scanning")

    except KeyboardInterrupt:
        logger.debug("Scan interrupted by user")
        scan_metadata["success"] = False
        scan_metadata["has_operational_errors"] = True
        _add_issue_to_model(
            results, "Scan interrupted by user", severity=IssueSeverity.INFO.value, details={"interrupted": True}
        )
    except Exception as e:
        report_path = _redacted_scan_path_for_reporting(local_source_report_path)
        if isinstance(e, _LocalSourceBoundaryError):
            scan_metadata["success"] = False
            scan_metadata["has_operational_errors"] = True
            _record_local_source_boundary_failure(results, local_source_report_path)
            aggregate_hash_complete = False
        else:
            report_error = _redacted_scan_error_for_reporting(e, local_source_report_path)
            if is_stream_url(local_source_report_path):
                logger.error(f"Error during scan: {report_error}")
            else:
                logger.exception(f"Error during scan: {report_error}")
            scan_metadata["success"] = False
            scan_metadata["has_operational_errors"] = True
            _add_issue_to_model(
                results,
                f"Error during scan: {report_error}",
                severity=IssueSeverity.INFO.value,
                details={"exception_type": type(e).__name__},
            )
            _add_error_asset_to_results(results, report_path)
    finally:
        try:
            if bound_local_source_path is not None and resolved_local_source_path is not None:
                results = _rebase_local_source_result(
                    results,
                    bound_local_source_path,
                    resolved_local_source_path,
                    local_source_report_path,
                )
                if (
                    bound_local_source_is_lexical_link
                    and expected_local_source_receipt is not None
                    and expected_local_source_receipt.get("mode_type") == stat.S_IFDIR
                ):
                    results = _rebase_symlinked_local_source_directory_descendants(
                        results,
                        local_source_report_path,
                        resolved_local_source_path,
                    )
        finally:
            path = local_source_report_path
            local_source_boundary_stack.close()
            _close_windows_shard_guards(windows_shard_guards)
            pickle_source_snapshot_stack.close()
            _deactivate_safetensors_index_inspection_context(index_context_token)

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
    results.has_errors = bool(scan_metadata.get("has_operational_errors", False))

    # Set success flag for backward compatibility
    results.success = not _results_should_be_unsuccessful(results)

    # Compute aggregate content hash only when every declared artifact was covered.
    if not aggregate_hash_complete:
        results.content_hash = None
    elif file_hashes:
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


def _bookkeeping_stat_size(stat_result: os.stat_result, max_bytes: int) -> int | None:
    if _stat_is_windows_reparse_point(stat_result):
        return None
    if not stat.S_ISREG(stat_result.st_mode):
        return None
    if stat_result.st_nlink != 1:
        return None
    if stat_result.st_size > max_bytes:
        return None
    return stat_result.st_size


def _same_bookkeeping_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _read_regular_bookkeeping_text(path_obj: Path, max_bytes: int) -> str | None:
    """Read a bounded regular bookkeeping file without following symlinks."""
    try:
        before_stat = path_obj.lstat()
    except OSError:
        return None
    if _bookkeeping_stat_size(before_stat, max_bytes) is None:
        return None

    fd: int | None = None
    try:
        fd = os.open(path_obj, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened_stat = os.fstat(fd)
        if not _same_bookkeeping_identity(before_stat, opened_stat):
            return None
        if _bookkeeping_stat_size(opened_stat, max_bytes) is None:
            return None

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_content = b"".join(chunks)
        if len(raw_content) > max_bytes:
            return None

        after_stat = os.fstat(fd)
        if not _same_bookkeeping_identity(opened_stat, after_stat):
            return None
        return raw_content.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd is not None:
            with suppress(OSError):
                os.close(fd)


def _has_scannable_bookkeeping_format(path_obj: Path) -> bool:
    try:
        return detect_file_format_for_skip_filter(str(path_obj)) != "unknown"
    except (OSError, ValueError, RecursionError):
        return True


def _hf_cache_relative_parts(path_obj: Path) -> tuple[Path, tuple[str, ...]] | None:
    hf_cache_root = _find_hf_cache_root(path_obj)
    if hf_cache_root is None:
        return None

    try:
        relative_parts = _resolve_hf_cache_path(path_obj).relative_to(hf_cache_root).parts
    except ValueError:
        return None
    return hf_cache_root, relative_parts


def _is_hf_no_exist_marker(path_obj: Path) -> bool:
    """Return True only for empty Hugging Face negative-cache markers."""
    cache_parts = _hf_cache_relative_parts(path_obj)
    if cache_parts is None:
        return False
    _hf_cache_root, relative_parts = cache_parts
    if not relative_parts or relative_parts[0] != ".no_exist":
        return False
    return _regular_bookkeeping_file_size(path_obj, 0) == 0


def _is_hf_ref_file(path_obj: Path) -> bool:
    """Return True for bounded Hugging Face ref files containing a commit digest."""
    cache_parts = _hf_cache_relative_parts(path_obj)
    if cache_parts is None:
        return False
    _hf_cache_root, relative_parts = cache_parts
    if not relative_parts or relative_parts[0] != "refs":
        return False
    content = _read_regular_bookkeeping_text(path_obj, _HF_CACHE_REF_MAX_BYTES)
    if content is None:
        return False
    lines = content.splitlines()
    return len(lines) == 1 and _is_hex_digest(lines[0].strip())


def _is_hf_hub_bookkeeping_path(path_obj: Path) -> bool:
    """Return True for bounded benign files under known Hugging Face hub cache directories."""
    cache_parts = _hf_cache_relative_parts(path_obj)
    if cache_parts is None:
        return False
    _hf_cache_root, relative_parts = cache_parts
    if not relative_parts or relative_parts[0] not in {"snapshots", "blobs"}:
        return False

    filename = path_obj.name
    if filename.endswith(".lock"):
        return _regular_bookkeeping_file_size(path_obj, 0) == 0
    if filename.endswith(".metadata"):
        content = _read_regular_bookkeeping_text(path_obj, _HF_DOWNLOAD_METADATA_MAX_BYTES)
        return content is not None and _is_hf_download_metadata_text(content)
    if filename in {".gitignore", ".gitattributes"}:
        content = _read_regular_bookkeeping_text(path_obj, _HF_HUB_GIT_BOOKKEEPING_MAX_BYTES)
        return content is not None and "\x00" not in content and not _has_scannable_bookkeeping_format(path_obj)
    return False


def _is_hf_download_bookkeeping_path(path_obj: Path) -> bool:
    """Return True for files stored in HuggingFace download bookkeeping directories."""
    import os

    resolved_path = _resolve_hf_cache_path(path_obj)
    configured_download_roots = {
        _resolve_hf_cache_path(root.parent / "download")
        for root in _get_hf_cache_roots()
        if root.parent.name.lower() == "huggingface"
    }
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        configured_download_roots.add(_resolve_hf_cache_path(Path(hf_home) / "download"))
    for download_root in configured_download_roots:
        try:
            resolved_path.relative_to(download_root)
        except ValueError:
            continue
        return _is_benign_local_hf_download_bookkeeping_file(
            path_obj,
            download_root=download_root,
            require_existing_target=False,
            allow_git_bookkeeping=True,
        )

    # Local snapshot downloads keep bookkeeping under the downloaded model
    # directory rather than the global cache root.
    local_download_root = _find_local_hf_download_root(path_obj)
    if local_download_root is None:
        return False

    local_model_root = local_download_root.parents[2]
    try:
        has_local_model_assets = any(child.is_file() for child in local_model_root.iterdir() if child.name != ".cache")
    except OSError:
        return False
    return _is_benign_local_hf_download_bookkeeping_file(
        path_obj,
        download_root=local_download_root,
        require_existing_target=True,
        allow_git_bookkeeping=has_local_model_assets,
    )


def _find_local_hf_download_root(path_obj: Path) -> Path | None:
    """Return the local `.cache/huggingface/download` root containing a sidecar path."""
    resolved_parent = _resolve_hf_cache_path(path_obj.parent)
    parts = resolved_parent.parts
    for index in range(0, len(parts) - 2):
        if tuple(part.lower() for part in parts[index : index + 3]) == (".cache", "huggingface", "download"):
            return Path(*resolved_parent.parts[: index + 3])
    return None


def _is_hex_digest(value: str) -> bool:
    if len(value) not in {40, 64}:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _is_hf_download_metadata_text(content: str) -> bool:
    """Return True for huggingface_hub local-dir download metadata files."""
    lines = content.splitlines()
    if len(lines) != 3:
        return False

    commit_hash, etag, timestamp = lines
    if not (_is_hex_digest(commit_hash) and _is_hex_digest(etag)):
        return False
    try:
        timestamp_value = float(timestamp)
    except ValueError:
        return False
    return math.isfinite(timestamp_value) and timestamp_value >= 0


def _download_sidecar_target_exists(path_obj: Path, download_root: Path) -> bool:
    """Return whether a local-dir sidecar maps to a real downloaded model file."""
    filename = path_obj.name
    if filename.endswith(".metadata"):
        target_name = filename[: -len(".metadata")]
    elif filename.endswith(".lock"):
        target_name = filename[: -len(".lock")]
    else:
        return False

    try:
        relative_parent = _resolve_hf_cache_path(path_obj.parent).relative_to(download_root)
    except ValueError:
        return False

    local_model_root = download_root.parents[2]
    return (local_model_root / relative_parent / target_name).is_file()


def _regular_bookkeeping_file_size(path_obj: Path, max_bytes: int) -> int | None:
    """Return regular-file size for HF bookkeeping candidates without following symlinks."""
    try:
        stat_result = path_obj.lstat()
    except OSError:
        return None
    return _bookkeeping_stat_size(stat_result, max_bytes)


def _is_benign_local_hf_download_bookkeeping_file(
    path_obj: Path,
    *,
    download_root: Path,
    require_existing_target: bool,
    allow_git_bookkeeping: bool,
) -> bool:
    """Return True only for local download bookkeeping files that do not look scannable."""
    filename = path_obj.name
    try:
        max_size = _HF_DOWNLOAD_METADATA_MAX_BYTES
        if filename in {".gitignore", ".gitattributes"}:
            max_size = _HF_DOWNLOAD_GIT_BOOKKEEPING_MAX_BYTES
        file_size = _regular_bookkeeping_file_size(path_obj, max_size)
        if file_size is None:
            return False
        if filename.endswith(".lock"):
            if require_existing_target and not _download_sidecar_target_exists(path_obj, download_root):
                return False
            return file_size == 0
        if filename.endswith(".metadata"):
            if require_existing_target and not _download_sidecar_target_exists(path_obj, download_root):
                return False
            content = _read_regular_bookkeeping_text(path_obj, _HF_DOWNLOAD_METADATA_MAX_BYTES)
            if content is None:
                return False
            return _is_hf_download_metadata_text(content)
        if filename in {".gitignore", ".gitattributes"}:
            if not allow_git_bookkeeping:
                return False
            content = _read_regular_bookkeeping_text(path_obj, _HF_DOWNLOAD_GIT_BOOKKEEPING_MAX_BYTES)
            return content is not None and "\x00" not in content and not _has_scannable_bookkeeping_format(path_obj)
    except (OSError, UnicodeDecodeError, RecursionError, ValueError):
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

    path_obj = Path(path)
    if _path_has_part(path_obj, ".no_exist") and _is_hf_no_exist_marker(path_obj):
        return True

    filename = os.path.basename(path)
    if not (
        filename.endswith((".lock", ".metadata"))
        or filename in {".gitignore", ".gitattributes", "main", "HEAD", "CACHEDIR.TAG"}
    ):
        return False

    # Only trust bookkeeping-shaped filenames when they actually live in a
    # recognized HuggingFace cache layout.
    if filename == "CACHEDIR.TAG":
        return _is_hf_cachedir_tag(path_obj)

    if filename in ["main", "HEAD"]:
        return _is_hf_ref_file(path_obj)

    is_hf_bookkeeping_path = _is_hf_hub_bookkeeping_path(path_obj) or _is_hf_download_bookkeeping_path(path_obj)
    if filename.endswith((".lock", ".metadata")):
        return is_hf_bookkeeping_path

    # Check for specific HuggingFace cache metadata files
    # We no longer skip all HuggingFace cache files since we handle symlinks properly now

    # Check for Git-related files that are commonly cached
    if filename in [".gitignore", ".gitattributes"]:
        return is_hf_bookkeeping_path

    return False


def _is_hf_cachedir_tag(path_obj: Path) -> bool:
    """Return True for Hugging Face's cache-directory tag file."""
    try:
        resolved_parent = _resolve_hf_cache_path(path_obj.parent)
        parent_parts = tuple(part.lower() for part in resolved_parent.parts[-2:])
        if parent_parts != (".cache", "huggingface"):
            return False
        content = _read_regular_bookkeeping_text(path_obj, _HF_CACHEDIR_TAG_MAX_BYTES)
        if content is None:
            return False
    except OSError:
        return False
    return content == _HF_CACHEDIR_TAG_CONTENT


def _has_hf_download_metadata_sidecar(path: str) -> bool:
    """Return whether a local file is backed by benign Hugging Face download metadata."""
    path_obj = Path(path)
    if _find_local_hf_download_root(path_obj) is not None:
        return False

    for local_root in path_obj.parents:
        download_root = local_root / ".cache" / "huggingface" / "download"
        if not download_root.is_dir():
            continue
        try:
            relative_path = path_obj.relative_to(local_root)
        except ValueError:
            continue
        metadata_path = download_root / relative_path.with_name(f"{relative_path.name}.metadata")
        if metadata_path.is_file() and _is_huggingface_cache_file(str(metadata_path)):
            return True
    return False


def _preserve_hf_download_sidecar_asset(
    path: str,
    scanner_selection_extensions: frozenset[str] | None,
) -> bool:
    """Return whether HF local-dir metadata should keep a skipped file in the inventory."""
    if scanner_selection_extensions is not None:
        return False
    return _has_hf_download_metadata_sidecar(path)


@cached_scan(cache_identity_config_key=_BOUND_CACHE_IDENTITY_CONFIG_KEY)
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
    configured_index_context = config.get(_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY)
    index_context_token, index_inspection_context = _activate_safetensors_index_inspection_context(
        configured_index_context if isinstance(configured_index_context, _SafetensorsIndexInspectionContext) else None
    )
    config[_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY] = index_inspection_context

    # Delegate to internal implementation - cache decorator handles caching
    try:
        result = _scan_file_internal(path, config)
        cache_identity_binding = config.get(_BOUND_CACHE_IDENTITY_CONFIG_KEY)
        if isinstance(cache_identity_binding, CacheIdentityBinding) and os.path.normcase(
            os.path.abspath(cache_identity_binding.scan_path)
        ) == os.path.normcase(os.path.abspath(path)):
            _rebase_pinned_shard_result(result, path, cache_identity_binding.identity_path)
        return result
    finally:
        _deactivate_safetensors_index_inspection_context(index_context_token)


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
    from modelaudit.scanners.zip_scanner import ZipPreflightRejected, ZipScanner

    allowed_shard_paths = _allowed_shard_paths_from_config(config)
    allowed_shard_targets = _validated_shard_targets_from_config(config)
    index_search_root = _shard_index_search_root_from_config(config)
    if allowed_shard_paths is not None:
        boundary_error = _grouped_shard_boundary_error(path, allowed_shard_paths, allowed_shard_targets)
        if boundary_error is not None:
            sr = ScanResult(scanner_name="shard_boundary")
            sr.add_check(
                name="Sharded Model Boundary Check",
                passed=False,
                message="Validated shard path changed before scanning; scan coverage is incomplete.",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    **boundary_error,
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_boundary_changed",
                },
            )
            _mark_operational_scan_error(sr, "shard_boundary_changed")
            _mark_inconclusive_scan_outcome(sr, "shard_boundary_changed")
            sr.finish(success=False)
            return sr
        config = dict(config)
        config.pop(_SHARD_FAMILY_CACHE_FINGERPRINT_CONFIG_KEY, None)

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

    bypass_cache_for_pytorch_read_limit = should_defer_hash_for_pytorch_read_limit(path, config, file_size)

    # Check if we should use extreme handler BEFORE applying size limits
    # Extreme handler bypasses size limits for large models
    use_extreme_handler = should_use_advanced_handler(
        path,
        allowed_shard_paths=allowed_shard_paths,
        allowed_shard_targets=allowed_shard_targets,
        index_search_root=index_search_root,
    )

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

    openvino_owner = _openvino_weights_companion_owner(Path(path))
    if openvino_owner is not None and _openvino_xml_companion_will_be_scanned(openvino_owner, config):
        sr = ScanResult(scanner_name="openvino")
        sr.bytes_scanned = file_size
        sr.metadata["file_size"] = file_size
        sr.metadata["openvino_xml_companion"] = str(openvino_owner)
        sr.add_check(
            name="OpenVINO Weights Sidecar Routing",
            passed=True,
            message="OpenVINO weights sidecar covered by adjacent XML model scan",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "xml_companion": str(openvino_owner),
                "sidecar_file": path,
            },
        )
        sr.finish(success=True)
        return sr

    hdf5_signature_offset = find_hdf5_signature_offset(path)
    safetensors_overlap_scanner_ids = detect_safetensors_overlap_scanner_ids(path)
    try:
        max_zip_entries = int(config.get("max_zip_entries", ZipScanner.DEFAULT_MAX_ENTRIES))
    except (TypeError, ValueError):
        max_zip_entries = ZipScanner.DEFAULT_MAX_ENTRIES
    max_zip_directory_size = ZipScanner.central_directory_size_limit(config)
    if (
        hdf5_signature_offset in (None, 0)
        and allows_zip_structure_analysis(scanner_selection, path)
        and ZipScanner.requires_preflight_result(
            path,
            max_zip_entries,
            max_zip_directory_size,
        )
    ):
        preflight_result = ZipScanner(config=config).scan(path)
        merge_safetensors_overlap_analysis(
            path,
            preflight_result,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        return preflight_result

    logger.debug(f"Processing: {path}")

    format_probe_error: OSError | None = None
    try:
        if os.path.isfile(path) and not os.access(path, os.R_OK):
            format_probe_error = PermissionError(f"Path is not readable: {path}")
    except OSError as e:
        format_probe_error = e

    try:
        follow_validated_symlink = _is_validated_bound_source_path(path, config)
        if follow_validated_symlink:
            config[VALIDATED_DESCRIPTOR_BOUND_SOURCE_CONFIG_KEY] = True
        header_format = (
            "unknown"
            if format_probe_error is not None
            else (
                detect_file_format(path, follow_validated_symlink=True)
                if follow_validated_symlink and detect_file_format is _VALIDATED_SYMLINK_DETECT_FILE_FORMAT
                else detect_file_format(path)
            )
        )
    except OSError as e:
        # Dedicated scanners can produce a format-specific inconclusive result
        # once extension routing selects their ownership.
        header_format = "unknown"
        format_probe_error = e
    ext_format = detect_format_from_extension(path)
    ext = os.path.splitext(path)[1].lower()
    pytorch_binary_supplemental_scanner_id = (
        detect_pytorch_binary_supplemental_format(path) if ext == ".bin" and header_format == "pytorch_binary" else None
    )
    if (
        format_probe_error is None
        and header_format in {"unknown", "pytorch_binary"}
        and pytorch_binary_supplemental_scanner_id is None
        and not (ext == ".model" and _is_malformed_sentencepiece_model_proto_candidate_file(path))
        and scanner_selection.allows("zip")
        and ZipScanner.can_handle(path)
    ):
        header_format = "zip"
    if format_probe_error is not None:
        magic_format = "unknown"
    elif header_format == "zip":
        magic_format = "zip"
    elif header_format in {"mxnet", MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT}:
        magic_format = header_format
    else:
        try:
            magic_format = (
                detect_file_format_from_magic(path, follow_validated_symlink=True)
                if follow_validated_symlink
                and detect_file_format_from_magic is _VALIDATED_SYMLINK_DETECT_FILE_FORMAT_FROM_MAGIC
                else detect_file_format_from_magic(path)
            )
        except OSError as e:
            magic_format = "unknown"
            format_probe_error = e
    skipped_overlap_scanner_id: str | None = None
    if (
        header_format == "xgboost"
        and scanner_selection.active
        and scanner_selection.allows("mxnet")
        and not scanner_selection.allows("xgboost")
    ):
        selected_mxnet_route = detect_mxnet_symbol_content_route(path)
        if selected_mxnet_route == "mxnet":
            header_format = magic_format = "mxnet"
            config[MXNET_PREFERRED_XGBOOST_SKIP_PATH_CONFIG_KEY] = str(Path(path).resolve())
            skipped_overlap_scanner_id = "xgboost"
        elif selected_mxnet_route == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
            header_format = magic_format = MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
            skipped_overlap_scanner_id = "xgboost"
    if (
        header_format in {"mxnet", MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT}
        and ext != ".json"
        and scanner_selection.active
        and scanner_selection.allows("xgboost")
        and not scanner_selection.allows("mxnet")
        and (
            XGBoostScanner._is_xgboost_json(
                path,
                max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES,
            )
            or XGBoostScanner._is_probable_mxnet_overlap_candidate(
                path,
                max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES,
            )
        )
    ):
        # Keep default bounded ownership with MXNet, but honor explicit
        # XGBoost-only coverage when its structure is already observable.
        header_format = magic_format = "xgboost"
    if (
        header_format == "xgboost"
        and ext != ".json"
        and (
            XGBoostScanner._is_xgboost_json(
                path,
                max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES,
            )
            or XGBoostScanner._is_probable_mxnet_overlap_candidate(
                path,
                max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES,
            )
        )
    ):
        configure_content_routed_json_scan(config, max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES)
    if int(config.get("_archive_depth", 0)) > 0 and magic_format == "unknown":
        nested_xgboost_route = detect_xgboost_ubjson_content_route(path)
        if nested_xgboost_route is not None:
            header_format = magic_format = nested_xgboost_route
            if nested_xgboost_route == "xgboost":
                config[XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY] = True
    is_xgboost_pickle_spoof = ext in _XGBOOST_BINARY_EXTENSIONS and header_format == "pickle"
    sentencepiece_model_proto_owned = (
        format_probe_error is None
        and ext == ".model"
        and header_format == "unknown"
        and magic_format == "unknown"
        and is_sentencepiece_model_proto_file(path)
    )
    # Record telemetry for file type detection
    detected_format = header_format if header_format != "unknown" else ext_format
    record_file_type_detected(path, detected_format)

    pickle_routing_inconclusive = (
        header_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT or magic_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT
    )
    pickle_overlap_uses_shard_handler = (
        pickle_routing_inconclusive
        and use_extreme_handler
        and ShardedModelDetector.detect_shards(
            path,
            allowed_paths=allowed_shard_paths,
            allowed_targets=allowed_shard_targets,
            index_search_root=index_search_root,
        )
        is not None
    )

    # Validate file type consistency as a security check
    if header_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT or magic_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT:
        sr = _make_incomplete_llamafile_routing_result(path, config)
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if header_format == NEMO_ROUTING_INCONCLUSIVE_FORMAT or magic_format == NEMO_ROUTING_INCONCLUSIVE_FORMAT:
        sr = _make_incomplete_nemo_routing_result(path)
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if (
        header_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
        or magic_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
    ):
        sr = _make_incomplete_mxnet_symbol_routing_result(path, config)
        if skipped_overlap_scanner_id:
            add_scanner_selection_skip_check(
                sr,
                path,
                skipped_overlap_scanner_id,
                scanner_selection,
                context="overlapping JSON analysis",
                kind=SCANNER_SELECTION_PREFERRED_KIND,
            )
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if (
        header_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
        or magic_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT
    ):
        sr = _make_incomplete_xgboost_ubjson_routing_result(path)
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if header_format == ONNX_ROUTING_INCONCLUSIVE_FORMAT or magic_format == ONNX_ROUTING_INCONCLUSIVE_FORMAT:
        sr = _make_incomplete_onnx_routing_result(path)
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if (
        header_format == SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT
        or magic_format == SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT
    ):
        sr = _make_incomplete_sentencepiece_model_proto_result(path)
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if pickle_routing_inconclusive and not pickle_overlap_uses_shard_handler:
        selected_safetensors_result = _scan_selected_safetensors_overlap(
            path,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        if selected_safetensors_result is not None:
            if selected_safetensors_result.bytes_scanned == 0 and file_size > 0:
                selected_safetensors_result.bytes_scanned = file_size
            return selected_safetensors_result
        sr = _make_incomplete_pickle_routing_result(path)
        merge_safetensors_overlap_analysis(
            path,
            sr,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if (
        header_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
        or magic_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT
    ):
        sr = _make_incomplete_tensorflow_protobuf_routing_result(path)
        merge_safetensors_overlap_analysis(
            path,
            sr,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr
    if (
        header_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT or magic_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT
    ) and hdf5_signature_offset is None:
        sr = _scan_executable_zip_polyglot(path, config)
        merge_safetensors_overlap_analysis(
            path,
            sr,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        if sr.bytes_scanned == 0 and file_size > 0:
            sr.bytes_scanned = file_size
        return sr

    if hdf5_signature_offset is not None:
        # A validated HDF5 superblock is stronger evidence than a suffix or
        # user-block prefix that resembles another format.
        file_type_valid = True
    elif (
        pickle_overlap_uses_shard_handler
        and "safetensors" in safetensors_overlap_scanner_ids
        and scanner_selection.active
        and scanner_selection.allows("safetensors")
        and not scanner_selection.allows("pickle")
    ):
        # The advanced handler must retain family expansion before the selected
        # SafeTensors owner resolves an otherwise ambiguous pickle route.
        file_type_valid = True
    elif format_probe_error is not None:
        # A failed content read is not evidence of spoofing. Let an owning
        # scanner produce a precise read-failure outcome when one exists.
        file_type_valid = True
    else:
        try:
            file_type_valid = validate_file_type_with_formats(path, magic_format, ext_format)
        except OSError as e:
            file_type_valid = True
            format_probe_error = e
    gzip_tar_trailing_status = (
        _gzip_tar_trailing_status_for_config(path, config)
        if (
            format_probe_error is None
            and ext == ".nemo"
            and (header_format == "gzip" or magic_format == "gzip")
            and header_format in {"gzip", "nemo", "tar"}
        )
        else None
    )
    discrepancy_msg = None

    if not file_type_valid:
        # File type validation failed - this is a security concern
        discrepancy_msg = (
            f"File type validation failed: extension indicates {ext_format} but magic bytes "
            f"indicate {magic_format}. This could indicate file spoofing or corruption."
        )
    elif (
        header_format != ext_format
        and header_format != "unknown"
        and ext_format != "unknown"
        and not (
            (ext_format == "pytorch_binary" and header_format in ["onnx", "zip", "pickle"] and ext == ".bin")
            or (ext_format == "pytorch_binary" and header_format == "pickle" and ext in [".pt", ".pth"])
            or (ext_format == "pickle" and header_format == "jax_checkpoint" and ext in [".ckpt", ".pickle"])
            or (ext_format == "keras" and header_format in ["zip", "hdf5"])
            or (ext_format == "protobuf" and header_format == "onnx" and ext == ".pb")
            or (ext_format == "skops" and header_format == "zip" and ext == ".skops")
        )
    ):
        # Suppress expected container-vs-extension differences for known wrapper formats.
        discrepancy_msg = f"File extension indicates {ext_format} but header indicates {header_format}."
        logger.debug(discrepancy_msg)

    # Prefer scanners based on trusted structure rather than the filename alone.
    preferred_scanner: type[BaseScanner] | None = None
    try:
        scanner_id = (
            "keras_h5"
            if hdf5_signature_offset is not None
            else _select_preferred_scanner_id(path, header_format, ext, config)
        )
        hdf5_userblock_supplemental_scanner_id = (
            _select_hdf5_userblock_supplemental_scanner_id(path, magic_format, ext, config)
            if scanner_id == "keras_h5" and hdf5_signature_offset not in (None, 0)
            else None
        )
        if (
            config.get(JAX_VERIFIED_ORBAX_SIBLING_CONFIG_KEY) is True
            and Path(path).name.lower() == "metadata.json"
            and scanner_selection.allows("jax_checkpoint")
        ):
            scanner_id = "jax_checkpoint"
    except ZipPreflightRejected as exc:
        merge_safetensors_overlap_analysis(
            path,
            exc.result,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        return exc.result
    skipped_preferred_scanner_id: str | None = None
    unavailable_preferred_scanner_id: str | None = None
    trusted_flax_overlap_scanner_id: str | None = None
    if scanner_id == "flax_msgpack" and not scanner_selection.allows(scanner_id):
        skipped_preferred_scanner_id = scanner_id
        trusted_flax_overlap_scanner_id = next(
            (
                overlap_scanner_id
                for overlap_scanner_id in detect_flax_msgpack_overlap_routes(path)
                if scanner_selection.allows(overlap_scanner_id)
            ),
            None,
        )
        if trusted_flax_overlap_scanner_id is not None:
            scanner_id = trusted_flax_overlap_scanner_id
    if scanner_id and (
        scanner_selection.allows(scanner_id)
        or (scanner_id == "protobuf_model_candidate" and allows_protobuf_model_candidate_analysis(scanner_selection))
    ):
        preferred_scanner = _registry.load_scanner_by_id(scanner_id)
        if preferred_scanner is None and magic_format != "unknown" and scanner_id != PROTOBUF_MODEL_CANDIDATE_FORMAT:
            unavailable_preferred_scanner_id = scanner_id
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
        "routed_format": header_format,
        "extension_format": ext_format,
        "file_type_valid": file_type_valid,
    }

    if (
        preferred_scanner
        and scanner_id
        and (
            scanner_id == trusted_flax_overlap_scanner_id
            or _preferred_scanner_can_handle(preferred_scanner, scanner_id, header_format, path, config)
        )
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
                    allowed_shard_paths=allowed_shard_paths,
                    allowed_shard_targets=allowed_shard_targets,
                    index_search_root=index_search_root,
                )  # Double timeout for extreme files
            elif use_large_handler:
                logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                result = scan_large_file(path, scanner, progress_callback, timeout)
            elif (
                is_xgboost_pickle_spoof
                or bypass_cache_for_pytorch_read_limit
                or (scanner_id == "nemo" and gzip_tar_trailing_status is not None)
            ):
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
        scanner_class = None
        if (
            skipped_preferred_scanner_id == "pytorch_binary"
            and pytorch_binary_supplemental_scanner_id is not None
            and scanner_selection.allows(pytorch_binary_supplemental_scanner_id)
        ):
            scanner_class = _registry.load_scanner_by_id(pytorch_binary_supplemental_scanner_id)
        if scanner_class is None and unavailable_preferred_scanner_id is not None:
            fallback_scanner_id = HEADER_FORMAT_TO_SCANNER_ID.get(magic_format)
            if (
                fallback_scanner_id
                and fallback_scanner_id != unavailable_preferred_scanner_id
                and scanner_selection.allows(fallback_scanner_id)
            ):
                scanner_class = _registry.load_scanner_by_id(fallback_scanner_id)
        elif scanner_class is None and not sentencepiece_model_proto_owned:
            scanner_class = _registry.get_scanner_for_path(
                path,
                scanner_selection=scanner_selection if scanner_selection.active else None,
            )
        if scanner_class:
            logger.debug(f"Using {scanner_class.name} scanner for {path}")
            scanner_config = config
            if unavailable_preferred_scanner_id is not None:
                scanner_config = dict(config)
                scanner_config["cache_enabled"] = False
            scanner = scanner_class(config=scanner_config)

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
                        allowed_shard_paths=allowed_shard_paths,
                        allowed_shard_targets=allowed_shard_targets,
                        index_search_root=index_search_root,
                    )  # Double timeout for extreme files
                elif use_large_handler:
                    logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                    result = scan_large_file(path, scanner, progress_callback, timeout)
                elif (
                    unavailable_preferred_scanner_id is not None
                    or is_xgboost_pickle_spoof
                    or bypass_cache_for_pytorch_read_limit
                    or (scanner_class.name == "nemo" and gzip_tar_trailing_status is not None)
                ):
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
            if unavailable_preferred_scanner_id is not None:
                result.merge(
                    _make_unavailable_recognized_format_result(
                        path,
                        unavailable_preferred_scanner_id,
                        unavailable_preferred_scanner_id,
                    )
                )
                # Refresh late metadata so incomplete coverage restores whitelist-downgraded findings.
                _mark_inconclusive_scan_outcome(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
                _mark_operational_scan_error(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
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
            if (
                unavailable_preferred_scanner_id is None
                and scanner_selection.active
                and not sentencepiece_model_proto_owned
            ):
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
                    userblock_zip_allowed = hdf5_signature_offset not in (
                        None,
                        0,
                    ) and allows_zip_content_analysis(scanner_selection)
                    if userblock_zip_allowed:
                        assert hdf5_signature_offset is not None
                        result.scanner_name = "zip"
                        merge_hdf5_userblock_zip_findings(
                            path,
                            result,
                            config,
                            hdf5_signature_offset,
                            context="HDF5 user-block ZIP",
                        )
                    merge_safetensors_overlap_analysis(
                        path,
                        result,
                        config,
                        scanner_selection,
                        safetensors_overlap_scanner_ids,
                    )
                    return result

            if unavailable_preferred_scanner_id is not None:
                sr = _make_unavailable_recognized_format_result(
                    path,
                    unavailable_preferred_scanner_id,
                    unavailable_preferred_scanner_id,
                )
            elif format_probe_error is not None and magic_format == "unknown":
                sr = _make_incomplete_format_detection_read_result(path, format_probe_error)
            elif magic_format == XML_MODEL_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_xml_model_result(path)
            elif header_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
                sr = _make_incomplete_protobuf_model_result(path)
            elif magic_format == PROTOBUF_MODEL_CANDIDATE_FORMAT and header_format != "unknown":
                sr = _make_unavailable_recognized_format_result(path, header_format, scanner_id)
            elif magic_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_llamafile_routing_result(path, config)
            elif magic_format == NEMO_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_nemo_routing_result(path)
            elif magic_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_mxnet_symbol_routing_result(path, config)
            elif magic_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_xgboost_ubjson_routing_result(path)
            elif magic_format == ONNX_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_onnx_routing_result(path)
            elif magic_format == SENTENCEPIECE_MODEL_PROTO_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_sentencepiece_model_proto_result(path)
            elif magic_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_pickle_routing_result(path)
            elif magic_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT:
                sr = _make_incomplete_tensorflow_protobuf_routing_result(path)
            elif magic_format == "unknown":
                # Not a recognized model format — skip silently
                sr = ScanResult(scanner_name="unknown")
                logger.debug(f"Skipping unrecognized format file: {path}")
            else:
                sr = _make_unavailable_recognized_format_result(path, magic_format, scanner_id)
            result = sr

    if skipped_overlap_scanner_id:
        add_scanner_selection_skip_check(
            result,
            path,
            skipped_overlap_scanner_id,
            scanner_selection,
            context="overlapping JSON analysis",
            kind=SCANNER_SELECTION_PREFERRED_KIND,
        )

    merge_safetensors_overlap_analysis(
        path,
        result,
        config,
        scanner_selection,
        safetensors_overlap_scanner_ids,
    )

    if is_xgboost_pickle_spoof:
        _mark_xgboost_pickle_extension_spoof(result, path, ext)

    if gzip_tar_trailing_status is not None and result.scanner_name == "nemo":
        has_integrity_check = any(
            check.name == "Compressed TAR Stream Integrity" and check.rule_code == "S902" for check in result.checks
        )
        if not has_integrity_check:
            integrity_message = (
                "Compressed TAR stream contains non-zero trailing data after archive EOF"
                if gzip_tar_trailing_status == "nonzero"
                else "Compressed TAR stream could not be fully validated after archive EOF"
            )
            result.add_check(
                name="Compressed TAR Stream Integrity",
                passed=False,
                message=integrity_message,
                severity=IssueSeverity.WARNING,
                location=path,
                details={"compression": "gzip", "stream_tail_status": gzip_tar_trailing_status},
                rule_code="S902",
            )
            _mark_inconclusive_scan_outcome(result, _COMPRESSED_TAR_STREAM_INCOMPLETE_REASON)
            _mark_operational_scan_error(result, _COMPRESSED_TAR_STREAM_INCOMPLETE_REASON)
            result.success = False

    if (
        skipped_preferred_scanner_id == "flax_msgpack"
        and trusted_flax_overlap_scanner_id is not None
        and result.scanner_name == trusted_flax_overlap_scanner_id
    ):
        add_scanner_selection_skip_check(
            result,
            path,
            skipped_preferred_scanner_id,
            scanner_selection,
            context="preferred scanner",
            kind=SCANNER_SELECTION_PREFERRED_KIND,
        )

    if result.scanner_name == "flax_msgpack":
        merge_flax_msgpack_overlap_findings(
            path,
            result,
            config,
            context="Flax MessagePack overlapping content analysis",
        )
    elif skipped_preferred_scanner_id == "flax_msgpack":
        merge_flax_msgpack_overlap_findings(
            path,
            result,
            config,
            context="Flax MessagePack overlapping content analysis",
            scanned_scanner_ids=frozenset({result.scanner_name}),
        )
    elif result.scanner_name != "flax_msgpack":
        merge_inconclusive_flax_msgpack_outcome(
            path,
            result,
            config,
            context="strict content owner overlapping ambiguous Flax analysis",
        )

    if hdf5_signature_offset not in (None, 0):
        assert hdf5_signature_offset is not None
        userblock_zip_allowed = allows_zip_content_analysis(scanner_selection)
        if userblock_zip_allowed:
            merge_hdf5_userblock_zip_findings(
                path,
                result,
                config,
                hdf5_signature_offset,
                context="HDF5 user-block ZIP",
            )
        elif hdf5_userblock_supplemental_scanner_id is not None:
            add_scanner_selection_skip_check(
                result,
                path,
                hdf5_userblock_supplemental_scanner_id,
                scanner_selection,
                context="HDF5 user-block content analysis",
            )
    if (
        hdf5_userblock_supplemental_scanner_id not in (None, "zip")
        and result.scanner_name != hdf5_userblock_supplemental_scanner_id
        and hdf5_userblock_supplemental_scanner_id not in safetensors_overlap_scanner_ids
    ):
        _merge_supplemental_scanner_analysis(
            path,
            result,
            config,
            scanner_selection,
            hdf5_userblock_supplemental_scanner_id,
            context="HDF5 user-block content analysis",
        )

    if ext == ".bin" and header_format == "pytorch_binary" and result.scanner_name == "pytorch_binary":
        _merge_pytorch_binary_supplemental_analysis(
            path,
            result,
            config,
            scanner_selection,
            pytorch_binary_supplemental_scanner_id,
        )

    if ext == ".json":
        _merge_jax_metadata_supplemental_analysis(path, result, config, scanner_selection)

    if discrepancy_msg:
        validated_alternate_format = (
            _validated_alternate_format_for_mismatch(
                result,
                header_format=header_format,
                magic_format=magic_format,
            )
            if not file_type_valid
            else None
        )
        if validated_alternate_format is not None:
            severity = IssueSeverity.INFO
            rule_code = None
            file_type_validation_failed = False
            detail_header_format = magic_format
            check_message = (
                f"File extension indicates {ext_format} but {validated_alternate_format} scanner validated "
                f"content indicated by {magic_format}. Filename and content disagree; using validated "
                "alternate-format analysis."
            )
        else:
            # Determine severity based on whether it's a validation failure or just a discrepancy
            severity = IssueSeverity.WARNING if not file_type_valid else IssueSeverity.DEBUG
            rule_code = "S901" if not file_type_valid else None
            file_type_validation_failed = not file_type_valid
            # For validation failures, use the actual magic format
            detail_header_format = magic_format if not file_type_valid else header_format
            check_message = discrepancy_msg + " Using header-based detection."
        details = {
            "extension_format": ext_format,
            "header_format": detail_header_format,
            "file_type_validation_failed": file_type_validation_failed,
        }
        if validated_alternate_format is not None:
            details.update(
                {
                    "alternate_format_validated": True,
                    "original_file_type_validation_failed": True,
                    "validated_format": validated_alternate_format,
                }
            )
            logger.info(check_message)
        elif not file_type_valid:
            logger.warning(discrepancy_msg)
        else:
            logger.debug(discrepancy_msg)
        result.add_check(
            name="Format Validation",
            passed=False,
            message=check_message,
            severity=severity,
            location=path,
            details=details,
            rule_code=rule_code,
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
    file_generator: Iterator[
        tuple[Path, bool]
        | tuple[Path, bool, ScanResult]
        | tuple[Path, bool, ScanResult | None, StreamedSourceByteAccounting]
    ],
    timeout: int = 3600,
    progress_callback: ProgressCallback | None = None,
    delete_after_scan: bool = True,
    scan_root: FilePath | None = None,
    shard_family_group: str | None = None,
    _trusted_shard_family_root: object | None = None,
    **kwargs: Any,
) -> ModelAuditResultModel:
    """
    Scan model files from a generator in streaming mode.

    Downloads files one at a time, scans immediately, computes hash, and optionally
    deletes to minimize disk usage. Computes aggregate content hash at the end.

    Args:
        file_generator: Generator yielding public path tuples or trusted internal scan/accounting tuples
        timeout: Scan timeout in seconds
        progress_callback: Optional callback for progress reporting
        delete_after_scan: Whether to delete files after scanning (default: True)
        scan_root: Optional root directory for local streaming traversal validation
        shard_family_group: Trusted source group, admitted only for recognized ephemeral staging parents
        _trusted_shard_family_root: Internal marker for a source-owned persistent staging root
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
    local_source_report_root = str(scan_root) if scan_root is not None else None
    local_source_boundary_stack = ExitStack()
    bound_local_source_path: str | None = None
    resolved_local_source_path: str | None = None
    local_source_receipt_value = kwargs.pop(_LOCAL_SOURCE_RECEIPT_CONFIG_KEY, None)
    expected_local_source_receipt = _validated_local_source_receipt(local_source_receipt_value)
    local_source_bound_guard_value = kwargs.pop(_LOCAL_SOURCE_BOUND_GUARD_CONFIG_KEY, None)
    local_source_bound_guard = (
        local_source_bound_guard_value if isinstance(local_source_bound_guard_value, _BoundLocalSourceGuard) else None
    )
    owned_local_source_guard: _BoundLocalSourceGuard | None = None
    bound_local_source_is_lexical_link = False
    local_source_initial_namespace: tuple[_DirectoryOwnerSnapshotEntry, ...] | None = None
    initial_local_source_entries: dict[tuple[str, ...], _DirectoryOwnerSnapshotEntry] = {}
    original_local_source_entry_paths: set[tuple[str, ...]] = set()
    observed_local_source_artifacts: set[tuple[str, ...]] = set()
    local_source_namespace_was_extended = False
    if expected_local_source_receipt is not None and local_source_bound_guard is None:
        current_receipt = (
            _snapshot_local_source_receipt(local_source_report_root) if local_source_report_root is not None else None
        )
        if not _local_source_receipts_match(expected_local_source_receipt, current_receipt):
            _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
            close_generator = getattr(file_generator, "close", None)
            if callable(close_generator):
                with suppress(Exception):
                    close_generator()
            results.finalize_statistics()
            return results
    file_hashes: list[str] = []
    hashed_stream_file_instances: set[tuple[Path, _FileIdentitySnapshot]] = set()
    hashed_stream_file_hashes_by_target: dict[_FileTargetIdentityKey, str] = {}
    hashed_stream_source_hashes_by_path: dict[Path, str] = {}
    hashed_stream_source_hashes_by_target: dict[_FileTargetIdentityKey, str] = {}
    counted_onnx_external_data_instances: set[tuple[Path, _FileIdentitySnapshot]] = set()
    counted_onnx_external_data_targets: set[_FileTargetIdentityKey] = set()
    consumed_onnx_external_data_aliases: dict[Path, _FileTargetIdentityKey] = {}
    terminal_hf_alias_targets: dict[Path, dict[str, int | str]] = {}
    aggregate_hash_complete = True
    top_level_hashed_bytes = 0
    files_processed = 0
    skip_file_types: bool = bool(kwargs.get("skip_file_types", False))
    scan_kwargs = normalize_scanner_selection_config(kwargs)
    local_source_snapshot_max_entries_value = scan_kwargs.get(
        "max_directory_owner_snapshot_entries",
        _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES,
    )
    local_source_snapshot_max_entries = (
        local_source_snapshot_max_entries_value
        if isinstance(local_source_snapshot_max_entries_value, int)
        and not isinstance(local_source_snapshot_max_entries_value, bool)
        and local_source_snapshot_max_entries_value > 0
        else _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES
    )
    local_source_snapshot_max_entries = max(
        local_source_snapshot_max_entries,
        _DEFAULT_MAX_DIRECTORY_OWNER_SNAPSHOT_ENTRIES,
    )
    try:
        max_total_size = int(scan_kwargs.get("max_total_size", 0) or 0)
    except (TypeError, ValueError):
        max_total_size = 0
    try:
        max_file_size = int(scan_kwargs.get("max_file_size", 0) or 0)
    except (TypeError, ValueError):
        max_file_size = 0
    scanner_selection = policy_from_config(scan_kwargs)
    scanner_selection_extensions = selected_scanner_extensions(scanner_selection) if scanner_selection.active else None
    if scanner_selection.active:
        results.scanner_selection = scanner_selection.to_metadata()
    repository_inventory_context: RepositoryFileInventory | None = None
    metadata_scanner_available: bool = scanner_selection.allows("metadata") and _registry.has_scanner_class(
        "MetadataScanner"
    )
    nearby_license_cache: dict[str, list[str]] = {}
    pending_delete_failures: dict[Path, Exception] = {}
    deleted_streamed_sources: set[str] = set()
    deleted_streamed_index_candidates: set[tuple[str, str]] = set()
    deferred_streamed_index_deletions: dict[Path, tuple[_FileIdentitySnapshot, str, bool]] = {}
    deferred_streamed_index_logical_paths: dict[Path, set[str]] = {}
    observed_streamed_safetensors_shard_parents: set[str] = set()
    validated_shard_targets: ValidatedShardTargets = {}
    stream_windows_shard_guards: _WindowsShardGuards = []
    preserved_openvino_companion_snapshots: dict[Path, _FileIdentitySnapshot] = {}
    deferred_openvino_sidecars: dict[Path, Path] = {}
    consumed_openvino_companions: set[Path] = set()
    preserve_shard_reconciliation_errors = False
    deleted_streamed_index_tracking_incomplete = False
    streamed_safetensors_scope_tracking_incomplete = False
    streamed_index_document_probe_bytes = 0
    streamed_index_cleanup_verification_bytes = 0
    deferred_streamed_index_bytes = 0
    streamed_index_retention_failed = False
    streamed_item_count = 0
    received_pretransferred_bytes = False
    stream_generator_closed = False

    def streaming_repository_inventory_context() -> RepositoryFileInventory:
        nonlocal repository_inventory_context

        configured_inventory = scan_kwargs.get(REPOSITORY_FILE_INVENTORY_CONFIG_KEY)
        if isinstance(configured_inventory, RepositoryFileInventory):
            repository_inventory_context = configured_inventory
            return configured_inventory

        if repository_inventory_context is None or not repository_inventory_context.files:
            repository_inventory_context = repository_file_inventory_context_from_config(scan_kwargs)
            if repository_inventory_context.files:
                scan_kwargs[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = repository_inventory_context

        return repository_inventory_context

    def normalized_stream_path(source_path: str | os.PathLike[str]) -> str:
        return os.path.normcase(os.path.normpath(os.path.abspath(source_path)))

    def canonical_stream_directory(directory: str | os.PathLike[str]) -> str:
        """Return one stable resolved directory identity, falling back to its absolute path."""
        directory_path = Path(directory)
        try:
            directory_path = directory_path.resolve(strict=True)
        except (OSError, RuntimeError):
            directory_path = directory_path.absolute()
        return os.path.normcase(os.path.normpath(str(directory_path)))

    def canonical_stream_parent(source_path: str | os.PathLike[str]) -> str:
        return canonical_stream_directory(Path(source_path).absolute().parent)

    def index_parent_can_govern_stream_parent(index_parent: str, shard_parent: str) -> bool:
        """Return whether canonical parents share the selected shard's ancestor search scope."""
        search_root = canonical_stream_index_search_root or shard_parent
        try:
            return (
                os.path.commonpath([index_parent, shard_parent]) == index_parent
                and os.path.commonpath([index_parent, search_root]) == search_root
            )
        except ValueError:
            return False

    def classify_structural_safetensors_index(
        source_path: Path,
        *,
        charge_budget: bool = True,
    ) -> tuple[bool | None, _FileIdentitySnapshot | None]:
        """Return True for an index, False for proven non-index content, or None when indeterminate."""
        nonlocal streamed_index_document_probe_bytes

        source_identity = _snapshot_file_identity(source_path)
        if source_identity is None or source_identity.stat is None or not stat.S_ISREG(source_identity.stat[2]):
            return None, source_identity
        source_size = _snapshot_file_size(source_identity)
        open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        index_fd: int | None = None
        try:
            index_fd = os.open(source_path, open_flags)
            opened_stat = os.fstat(index_fd)
            opened_identity = (
                opened_stat.st_dev,
                opened_stat.st_ino,
                opened_stat.st_mode,
                opened_stat.st_size,
                opened_stat.st_mtime_ns,
                opened_stat.st_ctime_ns,
            )
            if opened_identity != source_identity.stat or not stat.S_ISREG(opened_stat.st_mode):
                return None, None
            prefix_limit = min(source_size + 1, 4096)
            index_bytes = os.read(index_fd, prefix_limit)
            stripped_prefix = index_bytes.lstrip()
            prefix_is_complete = len(index_bytes) == source_size
            if (stripped_prefix and not stripped_prefix.startswith(b"{")) or (
                prefix_is_complete and not stripped_prefix
            ):
                post_read_stat = os.fstat(index_fd)
                if not os.path.samestat(opened_stat, post_read_stat):
                    return None, None
                return (
                    (False, source_identity)
                    if _snapshot_file_identity(source_path) == source_identity
                    else (None, None)
                )
            if source_size > MAX_SAFETENSORS_SHARD_INDEX_BYTES or (
                charge_budget
                and streamed_index_document_probe_bytes + source_size > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES
            ):
                return None, source_identity
            if charge_budget:
                streamed_index_document_probe_bytes += source_size
            remaining = source_size + 1 - len(index_bytes)
            index_buffer = bytearray(index_bytes)
            while remaining > 0:
                chunk = os.read(index_fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                index_buffer.extend(chunk)
                remaining -= len(chunk)
            index_bytes = bytes(index_buffer)
            post_read_stat = os.fstat(index_fd)
            if not os.path.samestat(opened_stat, post_read_stat):
                return None, None
        except (BlockingIOError, OSError):
            return None, None
        finally:
            if index_fd is not None:
                os.close(index_fd)
        if len(index_bytes) != source_size or _snapshot_file_identity(source_path) != source_identity:
            return None, None
        if not index_bytes.lstrip().startswith(b"{"):
            return False, source_identity
        try:
            index_doc = _load_safetensors_index_json(index_bytes)
        except Exception:
            return None, source_identity
        if not isinstance(index_doc, dict) or getattr(index_doc, "has_duplicate_keys", False):
            return None, source_identity
        if "weight_map" not in index_doc:
            return False, source_identity
        weight_map = index_doc["weight_map"]
        if (
            not isinstance(weight_map, dict)
            or not weight_map
            or not all(isinstance(target, str) for target in weight_map.values())
        ):
            return None, source_identity
        return True, source_identity

    def is_retained_authoritative_index(
        source_path: Path,
        structural_index_classification: bool | None,
    ) -> bool:
        """Return whether shard validation may still depend on this index path."""
        return (
            structural_index_classification is True
            or streamed_safetensors_scope_tracking_incomplete
            or any(
                index_parent_can_govern_stream_parent(canonical_stream_parent(source_path), shard_parent)
                for shard_parent in observed_streamed_safetensors_shard_parents
            )
        )

    def record_streamed_index_retention_failure(
        source_path: Path,
        message: str,
        *,
        reason: str = "safetensors_index_retention_limit_exceeded",
    ) -> None:
        """Make a retention-budget failure durable even when cleanup succeeds."""
        nonlocal aggregate_hash_complete, preserve_shard_reconciliation_errors, streamed_index_retention_failed

        aggregate_hash_complete = False
        preserve_shard_reconciliation_errors = True
        results.has_errors = True
        results.success = False
        if streamed_index_retention_failed:
            return
        streamed_index_retention_failed = True
        _add_issue_to_model(
            results,
            message,
            severity=IssueSeverity.INFO.value,
            location=str(source_path),
            details={
                "analysis_incomplete": True,
                "operational_error": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": reason,
            },
        )

    def delete_streamed_index_candidate(
        source_path: Path,
        context: str,
        *,
        track_candidate: bool,
        expected_identity: _FileIdentitySnapshot | None,
        expected_content_hash: str | None,
        require_proven_non_index: bool,
        require_content_hash: bool,
    ) -> None:
        """Move one bound index generation aside before validating and unlinking it."""
        nonlocal deleted_streamed_index_tracking_incomplete, streamed_index_cleanup_verification_bytes

        parent_fd: int | None = None
        tombstone_fd: int | None = None
        tombstone_path: Path | None = None
        moved_source = False
        try:
            canonical_parent = canonical_stream_parent(source_path)
            use_directory_fd = os.name != "nt"
            if use_directory_fd:
                parent_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_DIRECTORY", 0)
                parent_fd = os.open(source_path.parent, parent_flags)
                bound_parent_stat = os.fstat(parent_fd)
                canonical_parent = canonical_stream_parent(source_path)
                if not os.path.samestat(bound_parent_stat, os.stat(canonical_parent)):
                    raise OSError("SafeTensors index parent changed before cleanup")
            tombstone_fd, raw_tombstone_path = tempfile.mkstemp(
                prefix=".modelaudit-index-delete-",
                dir=canonical_parent,
            )
            tombstone_path = Path(raw_tombstone_path)
            os.close(tombstone_fd)
            tombstone_fd = None
            if parent_fd is not None:
                os.unlink(tombstone_path.name, dir_fd=parent_fd)
                os.rename(
                    source_path.name,
                    tombstone_path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            else:
                os.replace(source_path, tombstone_path)
            moved_source = True
            moved_identity = _snapshot_file_identity(tombstone_path)
            moved_classification: bool | None = None
            if require_proven_non_index:
                moved_classification, _moved_receipt = classify_structural_safetensors_index(
                    tombstone_path,
                    charge_budget=False,
                )
            moved_generation_matches = bool(
                expected_identity is not None
                and moved_identity is not None
                and moved_identity.lstat[:5] == expected_identity.lstat[:5]
                and (
                    (moved_identity.stat is None and expected_identity.stat is None)
                    or (
                        moved_identity.stat is not None
                        and expected_identity.stat is not None
                        and moved_identity.stat[:5] == expected_identity.stat[:5]
                    )
                )
            )
            if expected_identity is not None and not moved_generation_matches:
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index candidate changed before cleanup.",
                    reason="safetensors_index_changed_before_cleanup",
                )
            if require_proven_non_index and moved_classification is not False:
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index candidate changed before content-routed cleanup.",
                    reason="safetensors_index_changed_before_cleanup",
                )
            if require_content_hash:
                moved_size = _snapshot_file_size(moved_identity)
                if moved_size <= MAX_SAFETENSORS_SHARD_INDEX_BYTES and (
                    streamed_index_cleanup_verification_bytes + moved_size <= MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES
                ):
                    streamed_index_cleanup_verification_bytes += moved_size
                    moved_content_hash = compute_sha256_hash(tombstone_path)
                    content_hash_changed = expected_content_hash is None or moved_content_hash != expected_content_hash
                else:
                    content_hash_changed = require_proven_non_index is False
                if content_hash_changed:
                    record_streamed_index_retention_failure(
                        source_path,
                        "Content-routed index candidate changed after scanning.",
                        reason="safetensors_index_changed_before_cleanup",
                    )
            if track_candidate:
                normalized_source = normalized_stream_path(source_path)
                candidate_receipt = (normalized_source, canonical_parent)
                if (
                    candidate_receipt in deleted_streamed_index_candidates
                    or len(deleted_streamed_index_candidates) < MAX_SAFETENSORS_SHARD_INDEX_FILES
                ):
                    deleted_streamed_index_candidates.add(candidate_receipt)
                else:
                    deleted_streamed_index_tracking_incomplete = True
            if parent_fd is not None:
                os.unlink(tombstone_path.name, dir_fd=parent_fd)
            else:
                os.unlink(tombstone_path)
            try:
                if parent_fd is not None:
                    os.stat(source_path.name, dir_fd=parent_fd, follow_symlinks=False)
                else:
                    os.lstat(Path(canonical_parent) / source_path.name)
                source_recreated = True
            except FileNotFoundError:
                source_recreated = False
            if source_recreated:
                recreated_path = Path(canonical_parent) / source_path.name
                error = OSError("SafeTensors index path was recreated during cleanup")
                pending_delete_failures[recreated_path] = error
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index path was recreated during cleanup.",
                    reason="safetensors_index_recreated_during_cleanup",
                )
            else:
                deleted_streamed_sources.add(normalized_stream_path(source_path))
            logger.debug("Deleted %s %s after identity-bound quarantine", source_path, context)
        except Exception as error:
            logger.warning("Failed to delete %s %s: %s", source_path, context, error)
            pending_delete_failures[tombstone_path if moved_source and tombstone_path is not None else source_path] = (
                error
            )
            record_streamed_index_retention_failure(
                source_path,
                "SafeTensors index cleanup could not bind and remove the selected generation.",
                reason="safetensors_index_cleanup_failed",
            )
        finally:
            if tombstone_fd is not None:
                os.close(tombstone_fd)
            if parent_fd is not None:
                os.close(parent_fd)
            if not moved_source and tombstone_path is not None:
                with suppress(OSError):
                    os.unlink(tombstone_path)

    def delete_streamed_source(
        source_path: Path,
        context: str,
        *,
        defer_safetensors_index: bool = True,
        track_safetensors_index_candidate: bool = True,
        structural_index_classification: bool | None = None,
        structural_index_identity: _FileIdentitySnapshot | None = None,
        expected_content_hash: str | None = None,
        structural_index_classification_complete: bool = False,
        quarantine_proven_non_index: bool = False,
        require_content_hash: bool = False,
    ) -> None:
        nonlocal deferred_streamed_index_bytes

        is_index_suffix = source_path.name.lower().endswith(SAFETENSORS_INDEX_SUFFIX)
        if not (source_path.exists() or source_path.is_symlink()):
            if is_index_suffix and structural_index_classification_complete:
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index candidate disappeared before cleanup.",
                    reason="safetensors_index_disappeared_before_cleanup",
                )
            return
        if not delete_after_scan and not is_index_suffix:
            return
        if defer_safetensors_index and is_index_suffix:
            if not structural_index_classification_complete:
                structural_index_classification, structural_index_identity = classify_structural_safetensors_index(
                    source_path
                )
            should_retain_index = is_retained_authoritative_index(
                source_path,
                structural_index_classification,
            ) or (not delete_after_scan and structural_index_classification is not False)
        else:
            should_retain_index = False
        if should_retain_index:
            retained_source_path = Path(canonical_stream_parent(source_path)) / source_path.name
            source_identity = _snapshot_file_identity(retained_source_path)
            if source_identity is None:
                error = OSError("SafeTensors index could not be bound for deferred deletion")
                pending_delete_failures[retained_source_path] = error
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index could not be bound for deferred deletion.",
                    reason="safetensors_index_disappeared_before_retention",
                )
                return
            if source_identity.stat is None or not stat.S_ISREG(source_identity.stat[2]):
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index candidate is not a regular file; terminal validation is incomplete.",
                )
                delete_streamed_source(
                    source_path,
                    context,
                    defer_safetensors_index=False,
                    track_safetensors_index_candidate=False,
                )
                return
            source_size = _snapshot_file_size(source_identity)
            existing_receipt = deferred_streamed_index_deletions.get(retained_source_path)
            existing_identity = existing_receipt[0] if existing_receipt is not None else None
            projected_retained_bytes = (
                deferred_streamed_index_bytes + source_size
                if existing_identity is None
                else deferred_streamed_index_bytes - _snapshot_file_size(existing_identity) + source_size
            )
            if existing_identity != source_identity and (
                (
                    existing_identity is None
                    and len(deferred_streamed_index_deletions) >= MAX_SAFETENSORS_SHARD_INDEX_FILES
                )
                or source_size > MAX_SAFETENSORS_SHARD_INDEX_BYTES
                or projected_retained_bytes > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES
            ):
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index retention limit exceeded; terminal shard validation is incomplete.",
                )
                if existing_identity is not None:
                    deferred_streamed_index_bytes -= _snapshot_file_size(existing_identity)
                    deferred_streamed_index_deletions.pop(retained_source_path, None)
                delete_streamed_source(
                    retained_source_path,
                    context,
                    defer_safetensors_index=False,
                    track_safetensors_index_candidate=False,
                    structural_index_identity=source_identity,
                )
                return
            retained_content_hash = expected_content_hash or compute_sha256_hash(retained_source_path)
            if existing_identity is not None and existing_identity != source_identity:
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index changed while retained for terminal validation.",
                    reason="safetensors_index_changed_while_retained",
                )
            existing_content_hash = existing_receipt[1] if existing_receipt is not None else None
            if existing_content_hash is not None and existing_content_hash != retained_content_hash:
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index content changed while retained for terminal validation.",
                    reason="safetensors_index_changed_while_retained",
                )
            if existing_identity != source_identity or existing_content_hash != retained_content_hash:
                deferred_streamed_index_bytes = projected_retained_bytes
                deferred_streamed_index_deletions[retained_source_path] = (
                    source_identity,
                    retained_content_hash,
                    delete_after_scan,
                )
            deferred_streamed_index_logical_paths.setdefault(retained_source_path, set()).add(
                normalized_stream_path(source_path)
            )
            return
        if not delete_after_scan:
            return
        if is_index_suffix:
            delete_streamed_index_candidate(
                source_path,
                context,
                track_candidate=track_safetensors_index_candidate,
                expected_identity=structural_index_identity,
                expected_content_hash=expected_content_hash,
                require_proven_non_index=quarantine_proven_non_index,
                require_content_hash=require_content_hash or quarantine_proven_non_index,
            )
            return
        try:
            source_path.unlink()
            normalized_source = normalized_stream_path(source_path)
            deleted_streamed_sources.add(normalized_source)
            logger.debug(f"Deleted {source_path} {context}")
        except Exception as e:
            logger.warning(f"Failed to delete {source_path} {context}: {e}")
            pending_delete_failures[source_path] = e

    def delete_deferred_streamed_indexes(context: str) -> None:
        """Delete only the exact index generations retained through terminal validation."""
        nonlocal streamed_index_cleanup_verification_bytes

        for source_path, (expected_identity, expected_content_hash, should_delete) in tuple(
            deferred_streamed_index_deletions.items()
        ):
            current_identity = _snapshot_file_identity(source_path)
            if current_identity != expected_identity:
                error = OSError("SafeTensors index changed before deferred deletion")
                if should_delete:
                    pending_delete_failures[source_path] = error
                record_streamed_index_retention_failure(
                    source_path,
                    "SafeTensors index changed before terminal verification; validation is incomplete.",
                    reason="safetensors_index_changed_before_deferred_deletion",
                )
                continue
            if not should_delete:
                source_size = _snapshot_file_size(current_identity)
                if (
                    source_size > MAX_SAFETENSORS_SHARD_INDEX_BYTES
                    or streamed_index_cleanup_verification_bytes + source_size > MAX_SAFETENSORS_SHARD_INDEX_TOTAL_BYTES
                ):
                    record_streamed_index_retention_failure(
                        source_path,
                        "SafeTensors index terminal verification limit exceeded.",
                    )
                    continue
                streamed_index_cleanup_verification_bytes += source_size
                try:
                    current_content_hash = compute_sha256_hash(source_path)
                    content_identity = _snapshot_file_identity(source_path)
                except OSError:
                    current_content_hash = None
                    content_identity = None
                if current_content_hash != expected_content_hash or content_identity != current_identity:
                    record_streamed_index_retention_failure(
                        source_path,
                        "SafeTensors index content changed before terminal verification.",
                        reason="safetensors_index_changed_before_deferred_deletion",
                    )
                continue
            delete_streamed_source(
                source_path,
                context,
                defer_safetensors_index=False,
                track_safetensors_index_candidate=False,
                structural_index_identity=expected_identity,
                expected_content_hash=expected_content_hash,
                require_content_hash=True,
            )
            if not (source_path.exists() or source_path.is_symlink()):
                deleted_streamed_sources.update(deferred_streamed_index_logical_paths.get(source_path, set()))
        deferred_streamed_index_deletions.clear()
        deferred_streamed_index_logical_paths.clear()

    def adjusted_streamed_bytes(bytes_scanned: object, source_bytes_preaccounted: int) -> int:
        """Return an item's new byte contribution after exact-once source accounting."""
        if not isinstance(bytes_scanned, int) or isinstance(bytes_scanned, bool) or bytes_scanned < 0:
            raise ValueError("Streamed scan bytes must be a non-negative integer")
        return max(bytes_scanned - source_bytes_preaccounted, 0)

    def record_max_total_size_failure(location: str, *, projected_total: int | None = None) -> bool:
        """Record the shared streaming size failure after any accounting contribution."""
        nonlocal aggregate_hash_complete, preserve_shard_reconciliation_errors

        observed_total = results.bytes_scanned if projected_total is None else projected_total
        if max_total_size <= 0 or observed_total <= max_total_size:
            return False
        aggregate_hash_complete = False
        _add_issue_to_model(
            results,
            f"Total scan size limit exceeded: {observed_total} bytes (max: {max_total_size})",
            severity=IssueSeverity.INFO.value,
            location=location,
            details={
                "max_total_size": max_total_size,
                "projected_total_size": observed_total,
                "analysis_incomplete": True,
            },
        )
        results.has_errors = True
        preserve_shard_reconciliation_errors = True
        return True

    def record_shard_pin_failure(source_path: Path, error: _ShardPinUnavailableError) -> None:
        """Record a durable operational failure when a streamed shard cannot be pinned."""
        failure = ScanResult(scanner_name="shard_pin")
        _mark_inconclusive_scan_outcome(failure, "shard_pin_unavailable")
        _mark_operational_scan_error(failure, "shard_pin_unavailable")
        failure.add_check(
            name="Shard Scan Pinning",
            passed=False,
            message=f"Unable to bind shard to a stable scan path: {source_path.name}",
            severity=IssueSeverity.INFO,
            location=str(source_path),
            details={
                "error": "descriptor-bound shard pinning unavailable",
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": "shard_pin_unavailable",
            },
        )
        failure.finish(success=False)
        results.aggregate_scan_result(
            {
                "bytes_scanned": 0,
                "files_scanned": 1,
                "has_errors": True,
                "success": False,
                "issues": [],
                "checks": _serialize_streamed_records(
                    list(failure.checks),
                    str(source_path),
                    str(source_path),
                ),
                "scanners": [failure.scanner_name],
                "file_metadata": {str(source_path): dict(failure.metadata)},
            }
        )

    def record_terminal_shard_boundary_failure(source_path: str, reason: str) -> None:
        """Exclude one stale preserved shard and retain an operational boundary failure."""
        nonlocal aggregate_hash_complete, preserve_shard_reconciliation_errors

        validated_shard_targets.pop(source_path, None)
        preserve_shard_reconciliation_errors = True
        aggregate_hash_complete = False
        results.has_errors = True
        results.success = False
        if any(
            check.name == "Sharded Model Boundary Check"
            and check.location == source_path
            and check.details.get("reason") == reason
            for check in results.checks
        ):
            return
        results.checks.append(
            Check(
                name="Sharded Model Boundary Check",
                status=CheckStatus.FAILED,
                message="Validated streamed shard authority changed after scanning; scan coverage is incomplete.",
                severity=IssueSeverity.INFO,
                location=source_path,
                details={
                    "path": source_path,
                    "reason": reason,
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "scan_outcome": "inconclusive",
                    "scan_outcome_reason": "shard_boundary_changed",
                },
            )
        )

    def close_streaming_generator() -> None:
        """Close source-owned resources before terminal authority validation."""
        nonlocal stream_generator_closed

        if stream_generator_closed:
            return
        stream_generator_closed = True
        close_generator = getattr(file_generator, "close", None)
        if not callable(close_generator):
            return
        try:
            close_generator()
        except Exception as e:
            logger.warning(f"Failed to close streaming file generator: {e}")
            results.has_errors = True
            results.success = False
            _add_issue_to_model(
                results,
                f"Failed to close streaming file generator: {e}",
                severity=IssueSeverity.INFO.value,
                details={
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "exception_type": type(e).__name__,
                },
            )

    def record_openvino_companion_stability_failure(
        xml_path: Path,
        companion_path: Path,
        reason: str,
    ) -> None:
        """Record a durable operational failure when a streamed OpenVINO sidecar changes."""
        failure = ScanResult(scanner_name="openvino")
        _mark_inconclusive_scan_outcome(failure, reason)
        _mark_operational_scan_error(failure, reason)
        failure.add_check(
            name="OpenVINO Weights Companion Stability",
            passed=False,
            message="OpenVINO weights companion changed while preserving XML/BIN scan context",
            severity=IssueSeverity.INFO,
            location=str(companion_path),
            details={
                "xml_file": str(xml_path),
                "companion_file": str(companion_path),
                "analysis_incomplete": True,
                "scan_outcome": "inconclusive",
                "scan_outcome_reason": reason,
            },
        )
        failure.finish(success=False)
        results.aggregate_scan_result(
            {
                "bytes_scanned": 0,
                "files_scanned": 0,
                "has_errors": True,
                "success": False,
                "issues": _serialize_streamed_records(
                    list(failure.issues),
                    str(companion_path),
                    str(companion_path),
                ),
                "checks": _serialize_streamed_records(
                    list(failure.checks),
                    str(companion_path),
                    str(companion_path),
                ),
                "scanners": [failure.scanner_name],
                "file_metadata": {str(companion_path): dict(failure.metadata)},
            }
        )

    def append_streamed_file_hash(
        scan_path: Path,
        scan_config: dict[str, Any],
        *,
        progress_label: str,
        track_stream_source: bool = False,
        skip_if_stream_source_seen: bool = False,
        skip_if_stream_target_seen: bool = False,
    ) -> str | None:
        """Hash one streamed source once before it can be deleted or consumed."""
        nonlocal aggregate_hash_complete, top_level_hashed_bytes

        scan_path_key = Path(os.path.abspath(scan_path))
        if skip_if_stream_source_seen and scan_path_key in hashed_stream_source_hashes_by_path:
            return hashed_stream_source_hashes_by_path[scan_path_key]

        scan_path_identity = _snapshot_file_identity(scan_path)
        scan_target_key = _file_target_identity_key(scan_path, scan_path_identity)
        if (
            skip_if_stream_target_seen
            and scan_target_key is not None
            and scan_target_key in hashed_stream_file_hashes_by_target
        ):
            return hashed_stream_file_hashes_by_target[scan_target_key]
        if scan_path_identity is not None and (scan_path_key, scan_path_identity) in hashed_stream_file_instances:
            return None

        defer_hash_for_max_total_size = _should_defer_hash_for_max_total_size(
            scan_config,
            hashed_bytes=top_level_hashed_bytes,
        )
        defer_hash_for_max_file_size = _should_defer_hash_for_max_file_size(str(scan_path), scan_config)
        defer_hash_for_file_backed_hdf5 = _should_defer_hash_for_file_backed_hdf5(str(scan_path))
        defer_hash_for_file_backed_onnx = should_defer_hash_for_file_backed_onnx(str(scan_path), scan_config)
        defer_hash_for_pytorch_read_limit = should_defer_hash_for_pytorch_read_limit(str(scan_path), scan_config)
        if (
            defer_hash_for_max_total_size
            or defer_hash_for_max_file_size
            or defer_hash_for_file_backed_hdf5
            or defer_hash_for_file_backed_onnx
            or defer_hash_for_pytorch_read_limit
        ):
            aggregate_hash_complete = False
            return None
        if _should_defer_hash_for_safetensors_header_limit(str(scan_path), scan_config):
            return None

        if progress_callback:
            progress_callback(
                f"Hashing {progress_label}",
                (files_processed / (files_processed + 1)) * 100,
            )
        with suppress(OSError):
            top_level_hashed_bytes += scan_path.stat().st_size
        file_hash = compute_sha256_hash(scan_path)
        file_hashes.append(file_hash)
        if scan_path_identity is not None:
            hashed_stream_file_instances.add((scan_path_key, scan_path_identity))
        if scan_target_key is not None:
            hashed_stream_file_hashes_by_target.setdefault(scan_target_key, file_hash)
        if track_stream_source:
            hashed_stream_source_hashes_by_path[scan_path_key] = file_hash
            if scan_target_key is not None:
                hashed_stream_source_hashes_by_target.setdefault(scan_target_key, file_hash)
        return file_hash

    def append_streamed_openvino_companion_hash(
        xml_path: Path,
        companion_path: Path,
        scan_config: dict[str, Any],
    ) -> None:
        """Hash an OpenVINO sidecar only after preserving its directory boundary."""
        nonlocal aggregate_hash_complete

        if companion_path.is_symlink():
            try:
                resolved_companion = companion_path.resolve(strict=True)
                model_dir = xml_path.resolve(strict=True).parent
            except OSError:
                aggregate_hash_complete = False
                return
            if not is_within_directory(str(model_dir), str(resolved_companion)):
                aggregate_hash_complete = False
                return
        append_streamed_file_hash(
            companion_path,
            scan_config,
            progress_label=companion_path.name,
        )

    try:
        if (
            local_source_bound_guard is None
            and expected_local_source_receipt is None
            and local_source_report_root is not None
            and not is_stream_url(local_source_report_root)
            and not (
                isinstance(_trusted_shard_family_root, _TrustedStreamShardRoot)
                and _trusted_shard_family_root.token is _TRUSTED_STREAM_SHARD_ROOT_TOKEN
            )
        ):
            if os.name == "posix":
                try:
                    owned_local_source_guard = _open_bound_local_source(local_source_report_root)
                except (OSError, RuntimeError, ValueError) as error:
                    raise _LocalSourceBoundaryError("local streaming source could not be retained") from error
                local_source_bound_guard = owned_local_source_guard
                expected_local_source_receipt = owned_local_source_guard.receipt
                local_source_boundary_stack.callback(owned_local_source_guard.close)
            elif os.name == "nt":
                expected_local_source_receipt = _snapshot_local_source_receipt(local_source_report_root)
                if expected_local_source_receipt is None:
                    raise _LocalSourceBoundaryError("local streaming source could not be retained")
        if local_source_bound_guard is not None:
            if (
                expected_local_source_receipt is None
                or not _local_source_receipts_match(expected_local_source_receipt, local_source_bound_guard.receipt)
                or local_source_bound_guard.changed()
            ):
                raise _LocalSourceBoundaryError("retained local source changed before streaming traversal")
            bound_local_source_path = local_source_bound_guard.bound_path
            resolved_path_value = expected_local_source_receipt.get("resolved_path")
            if not isinstance(resolved_path_value, str):
                raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
            resolved_local_source_path = resolved_path_value
            bound_local_source_is_lexical_link = bool(
                local_source_bound_guard.guarded_entries
                and local_source_bound_guard.guarded_entries[-1][3].get("mode_type") == stat.S_IFLNK
            )
            scan_root = bound_local_source_path
        elif expected_local_source_receipt is not None:
            current_receipt = (
                _snapshot_local_source_receipt(local_source_report_root)
                if local_source_report_root is not None
                else None
            )
            if not _local_source_receipts_match(expected_local_source_receipt, current_receipt):
                raise _LocalSourceBoundaryError("local source changed before streaming traversal")
            local_source_boundary_stack.enter_context(
                _retain_windows_local_source_guards(
                    local_source_report_root or "<local-stream>",
                    expected_local_source_receipt,
                )
            )
            if expected_local_source_receipt.get("mode_type") == stat.S_IFDIR and os.name == "posix":
                bound_local_source_path = local_source_boundary_stack.enter_context(
                    _bound_local_source_directory(
                        local_source_report_root or "<local-stream>", expected_local_source_receipt
                    )
                )
                resolved_path_value = expected_local_source_receipt.get("resolved_path")
                if not isinstance(resolved_path_value, str):
                    raise _LocalSourceBoundaryError("local source receipt omitted its resolved path")
                resolved_local_source_path = resolved_path_value
                original_close = getattr(file_generator, "close", None)
                if callable(original_close):
                    original_close()
                from .utils.helpers.file_iterator import iterate_files_streaming

                file_generator = iterate_files_streaming(bound_local_source_path)
                scan_root = bound_local_source_path
    except Exception:
        local_source_boundary_stack.close()
        _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
        close_generator = getattr(file_generator, "close", None)
        if callable(close_generator):
            with suppress(Exception):
                close_generator()
        results.finalize_statistics()
        return results

    try:
        base_dir = (
            Path(scan_root).absolute()
            if scan_root is not None and bound_local_source_path is not None
            else (Path(scan_root).resolve() if scan_root is not None else None)
        )
        if (
            base_dir is not None
            and expected_local_source_receipt is not None
            and expected_local_source_receipt.get("mode_type") == stat.S_IFDIR
        ):
            try:
                local_source_initial_namespace = _capture_directory_owner_namespace(
                    base_dir,
                    None,
                    deadline=start_time + timeout,
                    max_entries=local_source_snapshot_max_entries,
                    trusted_root_symlink=bound_local_source_path is not None,
                )
            except (OSError, RuntimeError, TimeoutError) as error:
                raise _LocalSourceBoundaryError("local streaming namespace could not be retained") from error
            initial_local_source_entries = {entry.relative_parts: entry for entry in local_source_initial_namespace}
            original_local_source_entry_paths = set(initial_local_source_entries)
        configured_index_search_root = _shard_index_search_root_from_config(scan_kwargs)
        stream_index_search_root = configured_index_search_root or (str(base_dir) if base_dir is not None else None)
        canonical_stream_index_search_root = (
            canonical_stream_directory(stream_index_search_root) if stream_index_search_root is not None else None
        )
        hf_cache_root = (
            _find_hf_cache_root(
                Path(resolved_local_source_path) if resolved_local_source_path is not None else base_dir
            )
            if base_dir is not None
            else None
        )
        is_hf_cache = base_dir is not None and hf_cache_root is not None
        scanner_selection_skip_extensions = (
            None if is_hf_cache and scanner_selection.active else scanner_selection_extensions
        )
        stream_started = False
        configured_index_context = scan_kwargs.get(_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY)
        index_context_token, index_inspection_context = _activate_safetensors_index_inspection_context(
            configured_index_context
            if isinstance(configured_index_context, _SafetensorsIndexInspectionContext)
            else None
        )
        scan_kwargs[_SAFETENSORS_INDEX_CONTEXT_CONFIG_KEY] = index_inspection_context
    except Exception as error:
        close_generator = getattr(file_generator, "close", None)
        if callable(close_generator):
            with suppress(Exception):
                close_generator()
        local_source_boundary_stack.close()
        if isinstance(error, _LocalSourceBoundaryError):
            _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
            results.finalize_statistics()
            return results
        raise

    try:
        try:
            file_iterator = iter(file_generator)
        except TypeError as error:
            logger.error(f"Streaming file source is not iterable: {error}", exc_info=True)
            results.has_errors = True
            preserve_shard_reconciliation_errors = True
            aggregate_hash_complete = False
            _add_issue_to_model(
                results,
                f"Streaming file source is not iterable: {error}",
                severity=IssueSeverity.INFO.value,
                details={
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "exception_type": type(error).__name__,
                },
            )
            file_iterator = iter(())
        scanning_deferred_openvino_sidecars = False
        while True:
            try:
                streamed_item = next(file_iterator)
                stream_started = True
            except StopIteration:
                if not scanning_deferred_openvino_sidecars and deferred_openvino_sidecars:
                    file_iterator = iter((sidecar_path, True) for sidecar_path in deferred_openvino_sidecars.values())
                    scanning_deferred_openvino_sidecars = True
                    continue
                break
            except Exception as e:
                if not stream_started:
                    raise
                logger.error(f"Streaming source interrupted after partial scan: {e}")
                results.has_errors = True
                results.success = False
                preserve_shard_reconciliation_errors = True
                aggregate_hash_complete = False
                _add_issue_to_model(
                    results,
                    (
                        "Streaming source interrupted before all artifacts could be scanned; "
                        "partial results were preserved."
                    ),
                    severity=IssueSeverity.INFO.value,
                    details={
                        "analysis_incomplete": True,
                        "operational_error": True,
                        "operational_error_reason": _STREAMING_SOURCE_INTERRUPTED_REASON,
                        "exception_type": type(e).__name__,
                        "files_scanned_before_failure": results.files_scanned,
                        "scan_outcome": "inconclusive",
                        "scan_outcome_reason": _STREAMING_SOURCE_INTERRUPTED_REASON,
                        "scan_outcome_reasons": [_STREAMING_SOURCE_INTERRUPTED_REASON],
                    },
                    issue_type=_STREAMING_SOURCE_INTERRUPTED_REASON,
                )
                break

            streamed_item_count += 1
            precomputed_result: ScanResult | None = None
            source_bytes_preaccounted = 0
            pretransferred_bytes = 0
            reported_source_path: str | None = None
            if len(streamed_item) == 4:
                file_path, _is_last, precomputed_result, byte_accounting = streamed_item
                if not isinstance(byte_accounting, StreamedSourceByteAccounting):
                    raise TypeError("Invalid streamed source byte accounting metadata")
                pretransferred_bytes = byte_accounting.pretransferred_bytes
                source_bytes_preaccounted = byte_accounting.source_bytes_preaccounted
                reported_source_path = byte_accounting.source_path
            elif len(streamed_item) == 3:
                file_path, _is_last, precomputed_result = streamed_item
            elif len(streamed_item) == 2:
                file_path, _is_last = streamed_item
            else:
                raise ValueError("Streamed items must contain two, three, or four values")
            if precomputed_result is not None and not isinstance(precomputed_result, ScanResult):
                raise TypeError("Invalid precomputed streamed scan result")
            is_precomputed_streamed_result = precomputed_result is not None
            yielded_source_path = Path(file_path)
            yielded_source_key = Path(os.path.abspath(yielded_source_path))
            report_path = reported_source_path or str(yielded_source_path)
            source_path = yielded_source_path
            logical_source_path = source_path
            preserve_stream_family_path = bool(
                ShardedModelDetector.match_shard_filename(yielded_source_path.name) is not None
                or yielded_source_path.name.lower().endswith(SAFETENSORS_INDEX_SUFFIX)
            )
            if (
                not is_precomputed_streamed_result
                and bound_local_source_path is not None
                and local_source_report_root is not None
                and not preserve_stream_family_path
            ):
                try:
                    relative_source = Path(os.path.abspath(yielded_source_path)).relative_to(
                        Path(os.path.abspath(local_source_report_root))
                    )
                except ValueError:
                    pass
                else:
                    source_path = Path(bound_local_source_path).joinpath(*relative_source.parts)
            local_source_relative_parts: tuple[str, ...] | None = None
            if initial_local_source_entries and not is_precomputed_streamed_result:
                assert base_dir is not None
                relative_roots = [
                    Path(os.path.abspath(local_source_report_root)) if local_source_report_root is not None else None,
                    Path(os.path.abspath(base_dir)) if base_dir is not None else None,
                ]
                for relative_root in relative_roots:
                    if relative_root is None:
                        continue
                    try:
                        relative_path = Path(os.path.abspath(yielded_source_path)).relative_to(relative_root)
                    except ValueError:
                        continue
                    local_source_relative_parts = relative_path.parts
                    break
                if local_source_relative_parts is None:
                    raise _LocalSourceBoundaryError("streamed local source escaped its retained root")
                expected_stream_entry = initial_local_source_entries.get(local_source_relative_parts)
                guarded_stream_path = Path(base_dir).joinpath(*local_source_relative_parts)
                try:
                    guarded_stream_entry = _directory_owner_snapshot_entry(
                        guarded_stream_path,
                        local_source_relative_parts,
                    )
                except OSError as error:
                    raise _LocalSourceBoundaryError("streamed local source changed before processing") from error
                extended_index_generation_changed = bool(
                    expected_stream_entry is not None
                    and local_source_relative_parts not in original_local_source_entry_paths
                    and yielded_source_path.name.lower().endswith(SAFETENSORS_INDEX_SUFFIX)
                    and not _directory_owner_snapshot_entries_match(expected_stream_entry, guarded_stream_entry)
                )
                if expected_stream_entry is None or extended_index_generation_changed:
                    if guarded_stream_entry.entry_type not in {"file", "link"}:
                        raise _LocalSourceBoundaryError("streamed local source changed before processing")
                    for parent_depth in range(len(local_source_relative_parts)):
                        parent_parts = local_source_relative_parts[:parent_depth]
                        parent_path = Path(base_dir).joinpath(*parent_parts)
                        try:
                            parent_stat = os.stat(parent_path) if not parent_parts else parent_path.lstat()
                            current_parent_entry = _directory_owner_snapshot_entry(
                                parent_path,
                                parent_parts,
                                entry_stat=parent_stat,
                            )
                        except OSError as error:
                            raise _LocalSourceBoundaryError(
                                "streamed local source changed before processing"
                            ) from error
                        previous_parent_entry = initial_local_source_entries.get(parent_parts)
                        if previous_parent_entry is not None:
                            if previous_parent_entry.entry_type == "link" and current_parent_entry.entry_type == "link":
                                if not _directory_owner_snapshot_entries_match(
                                    previous_parent_entry,
                                    current_parent_entry,
                                ):
                                    raise _LocalSourceBoundaryError("streamed local source changed before processing")
                                try:
                                    resolved_parent = parent_path.resolve(strict=True)
                                except (OSError, RuntimeError) as error:
                                    raise _LocalSourceBoundaryError(
                                        "streamed local source changed before processing"
                                    ) from error
                                if not is_within_directory(str(base_dir), str(resolved_parent)):
                                    raise _LocalSourceBoundaryError("streamed local source escaped its retained root")
                                continue
                            if (
                                previous_parent_entry.entry_type != "directory"
                                or current_parent_entry.entry_type != "directory"
                                or any(
                                    getattr(previous_parent_entry, field) != getattr(current_parent_entry, field)
                                    for field in ("device", "inode", "mode", "raw_link_target")
                                )
                            ):
                                raise _LocalSourceBoundaryError("streamed local source changed before processing")
                        elif current_parent_entry.entry_type != "directory":
                            raise _LocalSourceBoundaryError("streamed local source changed before processing")
                        initial_local_source_entries[parent_parts] = current_parent_entry
                    initial_local_source_entries[local_source_relative_parts] = guarded_stream_entry
                    local_source_initial_namespace = tuple(
                        sorted(initial_local_source_entries.values(), key=lambda entry: entry.relative_parts)
                    )
                    local_source_namespace_was_extended = True
                elif not _directory_owner_snapshot_entries_match(expected_stream_entry, guarded_stream_entry):
                    _record_local_source_boundary_failure(results, report_path)
                    preserve_shard_reconciliation_errors = True
                    aggregate_hash_complete = False
                    if delete_after_scan:
                        delete_streamed_source(
                            yielded_source_path,
                            "after pre-scan generation change",
                            defer_safetensors_index=False,
                            structural_index_identity=_snapshot_file_identity(yielded_source_path),
                        )
                    continue
                observed_local_source_artifacts.add(local_source_relative_parts)
                for parent_depth in range(1, len(local_source_relative_parts)):
                    parent_parts = local_source_relative_parts[:parent_depth]
                    parent_entry = initial_local_source_entries.get(parent_parts)
                    if parent_entry is not None and parent_entry.entry_type == "link":
                        observed_local_source_artifacts.add(parent_parts)
            source_key = Path(os.path.abspath(source_path))
            if pretransferred_bytes:
                if received_pretransferred_bytes or streamed_item_count != 1:
                    raise ValueError("Pretransferred bytes must be reported exactly once on the first streamed item")
                received_pretransferred_bytes = True
                results.bytes_scanned += pretransferred_bytes
            if source_bytes_preaccounted and not received_pretransferred_bytes:
                raise ValueError("Source bytes cannot be preaccounted before pretransferred bytes are reported")
            if (
                pretransferred_bytes
                and not is_precomputed_streamed_result
                and record_max_total_size_failure(report_path)
            ):
                delete_streamed_source(source_path, "after streaming size limit")
                break
            if not is_precomputed_streamed_result and source_key in consumed_openvino_companions:
                continue
            scan_path = source_path
            pinned_scan_context: Any | None = None
            pinned_scan: Any | None = None
            pinned_local_alias = False
            pinned_local_source = False
            pinned_local_alias_companion_paths: dict[str, Path] = {}
            pinned_companion_targets: dict[str, tuple[str, dict[str, int | str]]] = {}
            is_hf_cache_symlink = False
            trusted_hf_alias_target: dict[str, int | str] | None = None
            trusted_hf_alias_logical_path: str | None = None
            preserve_source_after_scan = is_precomputed_streamed_result
            openvino_scan_companion_path: Path | None = None
            openvino_scan_companion_key: Path | None = None
            openvino_companion_pre_scan_identity: _FileIdentitySnapshot | None = None
            openvino_companion_bytes_scanned = 0
            onnx_external_data_pre_scan_identities: dict[Path, _FileIdentitySnapshot] = {}
            onnx_external_data_bytes_scanned = 0
            suppress_consumed_onnx_external_data_accounting = False
            openvino_sidecar_needs_independent_scan = False
            independent_openvino_sidecar_result: ScanResult | None = None
            independent_openvino_sidecar_path: Path | None = None
            preflight_scan_result: ScanResult | None = None
            file_hash: str | None = None
            structural_index_classification: bool | None = None
            structural_index_identity: _FileIdentitySnapshot | None = None
            structural_index_classification_complete = False
            content_routed_safetensors_index_payload = False

            # Check for interruption before starting work on the yielded file.
            try:
                check_interrupted()
            except KeyboardInterrupt:
                if not is_precomputed_streamed_result:
                    delete_streamed_source(source_path, "after streaming interruption")
                raise

            # Check timeout
            if time.time() - start_time > timeout:
                results.has_errors = True
                preserve_shard_reconciliation_errors = True
                aggregate_hash_complete = False
                logger.error(f"Streaming scan timeout after {timeout}s")
                if not is_precomputed_streamed_result:
                    delete_streamed_source(source_path, "after streaming timeout")
                break

            try:
                if precomputed_result is not None:
                    _normalize_unclassified_scan_failure(precomputed_result)
                    metadata_dict = dict(precomputed_result.metadata or {})
                    report_path = str(
                        metadata_dict.get("source_path") or metadata_dict.get("remote_source_path") or source_path
                    )
                    resolved_report_path = str(source_path)
                    operational_scan_failure = _scan_result_has_operational_error(precomputed_result)
                    if operational_scan_failure:
                        preserve_shard_reconciliation_errors = True
                    aggregate_hash_complete = False
                    scan_result_dict = {
                        "bytes_scanned": adjusted_streamed_bytes(
                            precomputed_result.bytes_scanned,
                            source_bytes_preaccounted,
                        ),
                        "files_scanned": 1,
                        "has_errors": operational_scan_failure,
                        "success": precomputed_result.success,
                        "issues": _serialize_streamed_records(
                            list(precomputed_result.issues or []),
                            report_path,
                            resolved_report_path,
                        ),
                        "checks": _serialize_streamed_records(
                            list(precomputed_result.checks or []),
                            report_path,
                            resolved_report_path,
                        ),
                        "scanners": [precomputed_result.scanner_name] if precomputed_result.scanner_name else [],
                        "file_metadata": {report_path: metadata_dict},
                    }
                    results.aggregate_scan_result(scan_result_dict)
                    asset = asset_from_scan_result(report_path, precomputed_result, metadata=metadata_dict)
                    if asset:
                        asset["is_streamed"] = True
                        asset["is_remote_header_only"] = bool(metadata_dict.get("remote_header_only"))
                        results.assets.extend(convert_assets_to_models([asset]))
                    files_processed += 1
                    if record_max_total_size_failure(report_path):
                        break
                    continue

                if base_dir is not None and _is_huggingface_cache_file(str(source_path)):
                    logger.debug(f"Skipping HuggingFace cache file: {source_path}")
                    continue

                if base_dir is not None:
                    logical_source_path = _local_source_logical_path(
                        source_path,
                        bound_local_source_path,
                        resolved_local_source_path,
                    )
                    resolved_path, is_hf_cache_symlink, entry_unavailable = _resolve_directory_scan_target(
                        source_path,
                        base_dir,
                        is_hf_cache=is_hf_cache,
                        hf_cache_root=hf_cache_root,
                        results=results,
                        preserve_bound_path=bound_local_source_path is not None,
                        hf_snapshot_path=logical_source_path,
                    )
                    if entry_unavailable:
                        results.has_errors = True
                        preserve_shard_reconciliation_errors = True
                    if resolved_path is None:
                        continue
                    if is_hf_cache_symlink:
                        trusted_hf_alias_target = _snapshot_regular_file_target(resolved_path)
                        trusted_hf_alias_logical_path = str(logical_source_path)
                    scan_path = resolved_path
                    if not scan_path.is_file():
                        aggregate_hash_complete = False
                        preserve_shard_reconciliation_errors = True
                        results.has_errors = True
                        _add_issue_to_model(
                            results,
                            "Special directory entry could not be scanned",
                            severity=IssueSeverity.INFO.value,
                            location=str(source_path),
                            details={
                                "analysis_incomplete": True,
                                "operational_error": True,
                                "scan_outcome": "inconclusive",
                                "scan_outcome_reason": _DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON,
                            },
                            issue_type=_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON,
                        )
                        continue
                    snapshot_path = Path(os.path.abspath(source_path))
                    route_hf_onnx_alias = is_hf_cache_symlink and _should_scan_hf_cache_alias_lexically_for_onnx(
                        logical_source_path,
                        hf_cache_root,
                    )
                    if (is_hf_cache_symlink and bound_local_source_path is not None) or route_hf_onnx_alias:
                        scan_path = snapshot_path
                consumed_onnx_external_data_target = consumed_onnx_external_data_aliases.get(
                    source_key,
                    consumed_onnx_external_data_aliases.get(yielded_source_key),
                )
                if consumed_onnx_external_data_target is not None:
                    source_identity = _snapshot_file_identity(scan_path)
                    source_target_key = _file_target_identity_key(scan_path, source_identity)
                    if source_target_key == consumed_onnx_external_data_target:
                        scanner_class = _registry.get_scanner_for_path(
                            str(scan_path),
                            scanner_selection=scanner_selection if scanner_selection.active else None,
                        )
                        if scanner_class is None:
                            continue
                        suppress_consumed_onnx_external_data_accounting = True
                    else:
                        consumed_onnx_external_data_aliases.pop(source_key, None)
                        consumed_onnx_external_data_aliases.pop(yielded_source_key, None)

                # Build config before skip filtering so bin-first OpenVINO
                # sidecars can wait for their selected XML owner.
                scan_config = {
                    "timeout": timeout - int(time.time() - start_time),
                    **scan_kwargs,
                }
                scan_repository_inventory_context = streaming_repository_inventory_context()
                if scan_repository_inventory_context.files:
                    scan_config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = scan_repository_inventory_context

                openvino_sidecar_owner = _openvino_weights_companion_owner(logical_source_path)
                if (
                    openvino_sidecar_owner is not None
                    and scanner_selection.allows("openvino")
                    and not scanning_deferred_openvino_sidecars
                ):
                    is_lfs_sidecar, _lfs_info = check_lfs_pointer(str(scan_path))
                    if not is_lfs_sidecar:
                        preserve_source_after_scan = True
                        deferred_openvino_sidecars.setdefault(Path(os.path.abspath(scan_path)), source_path)
                        sidecar_snapshot = _snapshot_file_identity(scan_path)
                        if sidecar_snapshot is not None:
                            preserved_openvino_companion_snapshots[Path(os.path.abspath(scan_path))] = sidecar_snapshot
                        continue

                scan_unconsumed_openvino_sidecar = (
                    openvino_sidecar_owner is not None
                    and scanner_selection.allows("openvino")
                    and scanning_deferred_openvino_sidecars
                )
                if (
                    skip_file_types
                    and not scan_unconsumed_openvino_sidecar
                    and should_skip_file(
                        str(source_path),
                        metadata_scanner_available=metadata_scanner_available,
                        scanner_selection_extensions=scanner_selection_skip_extensions,
                    )
                    and not _preserve_hf_download_sidecar_asset(str(source_path), scanner_selection_skip_extensions)
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

                if scanner_selection.allows("openvino") and _is_openvino_xml_path(logical_source_path):
                    candidate_companion = _openvino_xml_weights_companion(logical_source_path)
                    if candidate_companion is not None:
                        openvino_scan_companion_path = candidate_companion
                        openvino_scan_companion_key = Path(os.path.abspath(candidate_companion))
                        openvino_companion_pre_scan_identity = _snapshot_file_identity(candidate_companion)
                        openvino_companion_bytes_scanned = _snapshot_file_size(openvino_companion_pre_scan_identity)
                        preserved_snapshot = preserved_openvino_companion_snapshots.get(openvino_scan_companion_key)
                        if (
                            preserved_snapshot is not None
                            and openvino_companion_pre_scan_identity is not None
                            and preserved_snapshot != openvino_companion_pre_scan_identity
                        ):
                            record_openvino_companion_stability_failure(
                                scan_path,
                                candidate_companion,
                                "openvino_weights_changed_before_xml_scan",
                            )
                            preserve_shard_reconciliation_errors = True
                            aggregate_hash_complete = False

                # Build config dict for scan_file
                scan_config = {
                    "timeout": timeout - int(time.time() - start_time),
                    **scan_kwargs,
                }
                safetensors_shard_match = ShardedModelDetector.match_safetensors_shard_filename(source_path.name)
                if safetensors_shard_match is not None:
                    shard_parent = canonical_stream_parent(source_path)
                    if (
                        shard_parent in observed_streamed_safetensors_shard_parents
                        or len(observed_streamed_safetensors_shard_parents) < MAX_SAFETENSORS_SHARD_INDEX_DIRECTORIES
                    ):
                        observed_streamed_safetensors_shard_parents.add(shard_parent)
                    else:
                        streamed_safetensors_scope_tracking_incomplete = True
                source_safetensors_shard_info = (
                    ShardedModelDetector.detect_shards(
                        str(source_path),
                        index_search_root=stream_index_search_root,
                    )
                    if safetensors_shard_match is not None
                    else None
                )
                if safetensors_shard_match is not None and (
                    deleted_streamed_index_tracking_incomplete
                    or any(
                        index_parent_can_govern_stream_parent(deleted_parent, shard_parent)
                        for _deleted_path, deleted_parent in deleted_streamed_index_candidates
                    )
                ):
                    record_terminal_shard_boundary_failure(
                        str(source_path),
                        "safetensors_index_deleted_before_shard_validation",
                    )
                is_single_safetensors_stream = bool(
                    safetensors_shard_match is not None and safetensors_shard_match.get("expected_total_shards") == 1
                )
                single_source_shard_info = source_safetensors_shard_info if is_single_safetensors_stream else None
                raw_authoritative_shard_index_base = (
                    source_safetensors_shard_info.get("shard_index_base")
                    if isinstance(source_safetensors_shard_info, dict)
                    and isinstance(source_safetensors_shard_info.get("safetensors_index_path"), str)
                    and source_safetensors_shard_info.get("safetensors_index_declares_current_file") is True
                    and not source_safetensors_shard_info.get("safetensors_index_error")
                    else None
                )
                authoritative_shard_index_base = (
                    raw_authoritative_shard_index_base
                    if raw_authoritative_shard_index_base in {"zero", "one"}
                    else None
                )
                authoritative_shard_index_path = (
                    source_safetensors_shard_info.get("safetensors_index_path")
                    if authoritative_shard_index_base is not None
                    and isinstance(source_safetensors_shard_info, dict)
                    and isinstance(source_safetensors_shard_info.get("safetensors_index_path"), str)
                    else None
                )
                authoritative_shard_index_fingerprint = (
                    source_safetensors_shard_info.get("safetensors_index_fingerprint")
                    if authoritative_shard_index_path is not None
                    and isinstance(source_safetensors_shard_info, dict)
                    and isinstance(source_safetensors_shard_info.get("safetensors_index_fingerprint"), str)
                    else None
                )
                authoritative_shard_index_generation = (
                    source_safetensors_shard_info.get("safetensors_index_generation")
                    if authoritative_shard_index_path is not None
                    and isinstance(source_safetensors_shard_info, dict)
                    and isinstance(source_safetensors_shard_info.get("safetensors_index_generation"), int)
                    and not isinstance(source_safetensors_shard_info.get("safetensors_index_generation"), bool)
                    else None
                )
                if authoritative_shard_index_path is not None:
                    scan_config[_DEFER_SAFETENSORS_INDEX_CONTENT_REVALIDATION_CONFIG_KEY] = True
                scan_repository_inventory_context = streaming_repository_inventory_context()
                if scan_repository_inventory_context.files:
                    scan_config[REPOSITORY_FILE_INVENTORY_CONFIG_KEY] = scan_repository_inventory_context
                if base_dir is not None:
                    scan_config.setdefault(REPOSITORY_SCAN_ROOT_CONFIG_KEY, str(base_dir))
                    repository_member_base_dir = base_dir
                    configured_repository_root = scan_config.get(REPOSITORY_SCAN_ROOT_CONFIG_KEY)
                    if isinstance(configured_repository_root, str) and configured_repository_root.strip():
                        with suppress(OSError, RuntimeError, ValueError):
                            repository_member_base_dir = Path(configured_repository_root).resolve()
                    repository_current_file = _repository_member_path_for_scan(
                        str(source_path),
                        repository_member_base_dir,
                    )
                    if repository_current_file is not None:
                        scan_config[REPOSITORY_CURRENT_FILE_CONFIG_KEY] = repository_current_file
                initial_shard_target = _snapshot_validated_shard_target(
                    str(source_path),
                    resolved_path=str(scan_path),
                    family_group=shard_family_group,
                    family_group_policy="stream_staging",
                    trusted_root_marker=_trusted_shard_family_root,
                    authoritative_shard_index_base=authoritative_shard_index_base,
                    authoritative_shard_index_path=authoritative_shard_index_path,
                    authoritative_shard_index_fingerprint=authoritative_shard_index_fingerprint,
                    authoritative_shard_index_generation=authoritative_shard_index_generation,
                )
                selected_resolved_path = str(scan_path)
                pre_scan_shard_target: ValidatedShardTargets = {}
                if initial_shard_target:
                    initial_target = next(iter(initial_shard_target.values()))
                    resolved_target = initial_target.get("resolved_path")
                    if isinstance(resolved_target, str):
                        selected_resolved_path = resolved_target
                        try:
                            if not delete_after_scan:
                                _retain_windows_shard_guard(
                                    stream_windows_shard_guards,
                                    resolved_target,
                                    str(source_path),
                                    initial_target,
                                )
                            initial_copy_size = initial_target.get("size")
                            initial_copy_limit = initial_copy_size if isinstance(initial_copy_size, int) else None
                            for configured_limit in (max_file_size, max_total_size):
                                if configured_limit > 0:
                                    initial_copy_limit = (
                                        configured_limit
                                        if initial_copy_limit is None
                                        else min(initial_copy_limit, configured_limit)
                                    )
                            pending_pinned_scan_context = _pinned_shard_scan_path(
                                resolved_target,
                                initial_target,
                                copy_max_bytes=initial_copy_limit,
                                deadline=start_time + timeout,
                            )
                            pinned_scan = pending_pinned_scan_context.__enter__()
                            pinned_scan_context = pending_pinned_scan_context
                            scan_path = Path(pinned_scan.path)
                            pre_scan_shard_target = _snapshot_validated_shard_target(
                                str(source_path),
                                resolved_path=resolved_target,
                                family_group=shard_family_group,
                                family_group_policy="stream_staging",
                                trusted_root_marker=_trusted_shard_family_root,
                                authoritative_shard_index_base=authoritative_shard_index_base,
                                authoritative_shard_index_path=authoritative_shard_index_path,
                                authoritative_shard_index_fingerprint=authoritative_shard_index_fingerprint,
                                authoritative_shard_index_generation=authoritative_shard_index_generation,
                            )
                            scan_config[_SHARD_ALREADY_PINNED_CONFIG_KEY] = True
                            if is_single_safetensors_stream and single_source_shard_info is not None:
                                try:
                                    pinned_resolved_path = str(scan_path.resolve(strict=True))
                                    pinned_stat = os.stat(scan_path)
                                except (OSError, RuntimeError) as error:
                                    raise _ShardPinUnavailableError(
                                        "validated shard pin could not be snapshotted"
                                    ) from error
                                pinned_target = {
                                    **initial_target,
                                    "resolved_path": pinned_resolved_path,
                                    "device": pinned_stat.st_dev,
                                    "inode": pinned_stat.st_ino,
                                    "size": pinned_stat.st_size,
                                    "mtime_ns": pinned_stat.st_mtime_ns,
                                    "ctime_ns": pinned_stat.st_ctime_ns,
                                    "nlink": pinned_stat.st_nlink,
                                }
                                bound_shard_info = _rebase_prevalidated_shard_info(
                                    single_source_shard_info,
                                    str(source_path),
                                    str(scan_path),
                                )
                                assert isinstance(bound_shard_info, dict)
                                bound_shard_info["current_file"] = str(scan_path)
                                bound_shard_info["shards"] = [str(scan_path)]
                                bound_shard_info["shard_targets"] = {str(scan_path): pinned_target}
                                scan_config[_PREVALIDATED_SHARD_INFO_CONFIG_KEY] = bound_shard_info
                                scan_config["cache_enabled"] = False
                        except _ShardPinUnavailableError as error:
                            if pinned_scan_context is not None:
                                pinned_scan_context.__exit__(type(error), error, error.__traceback__)
                            pinned_scan_context = None
                            record_shard_pin_failure(source_path, error)
                            preserve_shard_reconciliation_errors = True
                            aggregate_hash_complete = False
                            files_processed += 1
                            continue

                def initial_stream_target(candidate_path: Path) -> dict[str, int | str] | None:
                    if base_dir is not None:
                        try:
                            relative_candidate = Path(os.path.abspath(candidate_path)).relative_to(
                                Path(os.path.abspath(base_dir))
                            )
                        except ValueError:
                            pass
                        else:
                            initial_entry = initial_local_source_entries.get(relative_candidate.parts)
                            if initial_entry is not None and initial_entry.entry_type == "file":
                                return {
                                    "resolved_path": os.path.realpath(candidate_path),
                                    "device": initial_entry.device,
                                    "inode": initial_entry.inode,
                                    "size": initial_entry.size,
                                    "mtime_ns": initial_entry.mtime_ns,
                                    "ctime_ns": initial_entry.ctime_ns,
                                    "nlink": initial_entry.link_count,
                                }
                    return _snapshot_regular_file_target(candidate_path)

                def stream_pinned_companions(
                    logical_scan_path: Path,
                    openvino_companion: Path | None,
                    current_scan_config: dict[str, Any],
                ) -> tuple[
                    dict[str, tuple[str, dict[str, int | str]]],
                    dict[str, Path],
                    tuple[Path, int] | None,
                ]:
                    nonlocal aggregate_hash_complete
                    targets: dict[str, tuple[str, dict[str, int | str]]] = {}
                    logical_paths: dict[str, Path] = {}
                    oversized_companion: tuple[Path, int] | None = None
                    companion_paths: list[Path] = []
                    context_only_companions: set[Path] = set()
                    if openvino_companion is not None:
                        companion_paths.append(openvino_companion)
                    if scanner_selection.allows("mxnet"):
                        companion_paths.extend(_mxnet_companion_paths(logical_scan_path))
                    if scanner_selection.allows("oci_layer"):
                        context_only_companions.update(_oci_manifest_layer_companion_paths(logical_scan_path))
                        companion_paths.extend(context_only_companions)
                    if scanner_selection.allows("onnx") and not _should_defer_hash_for_max_file_size(
                        str(logical_scan_path),
                        current_scan_config,
                    ):
                        discovered_paths = _streamed_onnx_external_data_hash_paths(
                            logical_scan_path,
                            deadline=start_time + timeout,
                        )
                        if discovered_paths is None:
                            aggregate_hash_complete = False
                        else:
                            companion_paths.extend(discovered_paths)
                    for companion_path in dict.fromkeys(companion_paths):
                        try:
                            relative_companion_path = str(companion_path.relative_to(logical_scan_path.parent))
                        except ValueError:
                            aggregate_hash_complete = False
                            continue
                        companion_source = companion_path
                        if (
                            is_hf_cache
                            and hf_cache_root is not None
                            and _is_hf_cache_snapshot_alias(companion_path, hf_cache_root)
                        ):
                            trusted_blobs_root = _trusted_hf_blobs_root(hf_cache_root)
                            with suppress(OSError, RuntimeError):
                                resolved_companion = companion_path.resolve(strict=True)
                                if trusted_blobs_root is not None and is_within_directory(
                                    str(trusted_blobs_root),
                                    str(resolved_companion),
                                ):
                                    companion_source = resolved_companion
                        companion_target = initial_stream_target(companion_source)
                        if companion_target is None:
                            aggregate_hash_complete = False
                            continue
                        context_only = companion_path in context_only_companions
                        if context_only:
                            companion_target[CONTEXT_ONLY_COMPANION_TARGET_KEY] = 1
                        companion_size = companion_target.get("size")
                        if (
                            not context_only
                            and isinstance(companion_size, int)
                            and _should_defer_hash_for_max_file_size(
                                str(companion_path),
                                current_scan_config,
                                file_size=companion_size,
                            )
                        ):
                            oversized_companion = (companion_path, companion_size)
                            continue
                        targets[relative_companion_path] = (
                            str(companion_target["resolved_path"]),
                            companion_target,
                        )
                        logical_paths[relative_companion_path] = companion_path
                    return targets, logical_paths, oversized_companion

                def projected_stage_total(
                    primary_path: Path,
                    primary_target: dict[str, int | str],
                    companion_targets: Mapping[str, tuple[str, dict[str, int | str]]],
                    companion_paths: Mapping[str, Path],
                    *,
                    primary_already_accounted: bool,
                ) -> int:
                    """Project only unique, not-yet-accounted bytes that private staging would add."""
                    staged_bytes = results.bytes_scanned
                    seen_targets: set[tuple[object, ...]] = set()

                    def contribution(
                        path: Path,
                        candidate_target: dict[str, int | str],
                        already_accounted: bool,
                    ) -> int:
                        if candidate_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY):
                            return 0
                        target_key = _file_target_identity_key(path, _snapshot_file_identity(path))
                        logical_path_key = Path(os.path.abspath(path))
                        stable_key: tuple[object, ...] = (
                            candidate_target.get("device"),
                            candidate_target.get("inode"),
                            candidate_target.get("size"),
                            candidate_target.get("mtime_ns"),
                            candidate_target.get("ctime_ns"),
                        )
                        if stable_key in seen_targets:
                            return 0
                        seen_targets.add(stable_key)
                        accounted_target_keys = (
                            hashed_stream_file_hashes_by_target.keys()
                            | hashed_stream_source_hashes_by_target.keys()
                            | counted_onnx_external_data_targets
                        )
                        accounted_by_validated_identity = any(
                            len(accounted_key) >= 7
                            and accounted_key[0] == "stat"
                            and (
                                accounted_key[1],
                                accounted_key[2],
                                accounted_key[4],
                                accounted_key[5],
                                accounted_key[6],
                            )
                            == stable_key
                            for accounted_key in accounted_target_keys
                        )
                        if (
                            already_accounted
                            or (
                                target_key is not None
                                and consumed_onnx_external_data_aliases.get(logical_path_key) == target_key
                            )
                            or (
                                target_key is not None
                                and (
                                    target_key in hashed_stream_file_hashes_by_target
                                    or target_key in hashed_stream_source_hashes_by_target
                                    or target_key in counted_onnx_external_data_targets
                                )
                            )
                            or accounted_by_validated_identity
                        ):
                            return 0
                        target_size = candidate_target.get("size")
                        return target_size if isinstance(target_size, int) else 0

                    staged_bytes += contribution(primary_path, primary_target, primary_already_accounted)
                    for relative_name, (_resolved_path, companion_target) in companion_targets.items():
                        companion_path = companion_paths.get(relative_name)
                        if companion_path is None:
                            continue
                        staged_bytes += contribution(companion_path, companion_target, False)
                    return staged_bytes

                pin_target: dict[str, int | str] | None = None
                pin_resolved_path: str | None = None
                pin_logical_path = logical_source_path
                pin_is_alias = False
                pin_requires_regular_path = False
                if is_hf_cache_symlink and not initial_shard_target:
                    pin_target = trusted_hf_alias_target
                    candidate_pin_resolved_path = pin_target.get("resolved_path") if pin_target is not None else None
                    pin_resolved_path = (
                        candidate_pin_resolved_path if isinstance(candidate_pin_resolved_path, str) else None
                    )
                    pin_logical_path = (
                        Path(trusted_hf_alias_logical_path)
                        if trusted_hf_alias_logical_path is not None
                        else logical_source_path
                    )
                    pin_is_alias = True
                elif (
                    bound_local_source_path is not None and not initial_shard_target and not preserve_stream_family_path
                ):
                    pin_target = initial_stream_target(scan_path)
                    candidate_pin_resolved_path = pin_target.get("resolved_path") if pin_target is not None else None
                    pin_resolved_path = (
                        candidate_pin_resolved_path if isinstance(candidate_pin_resolved_path, str) else None
                    )
                    pin_requires_regular_path = True

                if pin_target is not None or pin_is_alias or pin_requires_regular_path:
                    source_size = pin_target.get("size") if pin_target is not None else None
                    if not isinstance(pin_resolved_path, str) or not isinstance(source_size, int):
                        _record_local_source_boundary_failure(results, report_path)
                        preserve_shard_reconciliation_errors = True
                        aggregate_hash_complete = False
                        files_processed += 1
                        continue
                    assert pin_target is not None
                    oversized_companion: tuple[Path, int] | None = None
                    pinned_companion_targets = {}
                    if _should_defer_hash_for_max_file_size(
                        str(pin_logical_path),
                        scan_config,
                        file_size=source_size,
                    ):
                        pinned_local_alias_companion_paths = {}
                        preflight_scan_result = _max_file_size_failure_scan_result(
                            report_path,
                            source_size,
                            max_file_size,
                        )
                        aggregate_hash_complete = False
                    else:
                        (
                            pinned_companion_targets,
                            pinned_local_alias_companion_paths,
                            oversized_companion,
                        ) = stream_pinned_companions(
                            pin_logical_path,
                            openvino_scan_companion_path,
                            scan_config,
                        )
                    if oversized_companion is not None:
                        oversized_path, oversized_size = oversized_companion
                        preflight_scan_result = _max_file_size_failure_scan_result(
                            str(oversized_path),
                            oversized_size,
                            max_file_size,
                        )
                        aggregate_hash_complete = False
                    if preflight_scan_result is None:
                        projected_stage_bytes = projected_stage_total(
                            pin_logical_path,
                            pin_target,
                            pinned_companion_targets,
                            pinned_local_alias_companion_paths,
                            primary_already_accounted=suppress_consumed_onnx_external_data_accounting,
                        )
                        if record_max_total_size_failure(report_path, projected_total=projected_stage_bytes):
                            break
                        copy_targets = [
                            pin_target,
                            *(target for _path, target in pinned_companion_targets.values()),
                        ]
                        try:
                            pending_pinned_scan_context = _pinned_shard_scan_path(
                                pin_resolved_path,
                                pin_target,
                                logical_path=str(pin_logical_path),
                                companion_targets=pinned_companion_targets,
                                require_regular_path=pin_requires_regular_path or bool(pinned_companion_targets),
                                copy_max_bytes=sum(
                                    copy_size
                                    for copy_target in copy_targets
                                    if not copy_target.get(CONTEXT_ONLY_COMPANION_TARGET_KEY)
                                    if isinstance((copy_size := copy_target.get("size")), int)
                                ),
                                deadline=start_time + timeout,
                            )
                            pinned_scan = pending_pinned_scan_context.__enter__()
                            pinned_scan_context = pending_pinned_scan_context
                            pinned_local_alias = pin_is_alias
                            pinned_local_source = not pin_is_alias
                            scan_path = Path(pinned_scan.path)
                            selected_resolved_path = pin_resolved_path
                            scan_config["cache_enabled"] = False
                        except _ShardPinUnavailableError:
                            if pinned_scan_context is not None:
                                pinned_scan_context.__exit__(None, None, None)
                            pinned_scan_context = None
                            _record_local_source_boundary_failure(results, report_path)
                            preserve_shard_reconciliation_errors = True
                            aggregate_hash_complete = False
                            files_processed += 1
                            continue

                defer_hash_for_pytorch_read_limit = should_defer_hash_for_pytorch_read_limit(
                    str(scan_path),
                    scan_config,
                )
                defer_hash_for_file_backed_onnx = should_defer_hash_for_file_backed_onnx(
                    str(scan_path),
                    scan_config,
                )
                if defer_hash_for_pytorch_read_limit:
                    scan_config = dict(scan_config)
                    scan_config["cache_enabled"] = False

                file_hash = append_streamed_file_hash(
                    scan_path,
                    scan_config,
                    progress_label=source_path.name,
                    track_stream_source=True,
                    skip_if_stream_target_seen=suppress_consumed_onnx_external_data_accounting,
                )
                if openvino_scan_companion_path is not None:
                    append_streamed_openvino_companion_hash(
                        scan_path,
                        openvino_scan_companion_path,
                        scan_config,
                    )
                if scanner_selection.allows("onnx") and not _should_defer_hash_for_max_file_size(
                    str(scan_path),
                    scan_config,
                ):
                    discovered_external_data_paths = _streamed_onnx_external_data_hash_paths(
                        scan_path,
                        deadline=start_time + timeout,
                    )
                    if discovered_external_data_paths is None:
                        aggregate_hash_complete = False
                    for onnx_external_data_path in discovered_external_data_paths or ():
                        external_data_key = Path(os.path.abspath(onnx_external_data_path))
                        external_data_identity = _snapshot_file_identity(onnx_external_data_path)
                        external_data_target_key = _file_target_identity_key(
                            onnx_external_data_path,
                            external_data_identity,
                        )
                        external_data_was_stream_source = external_data_key in hashed_stream_source_hashes_by_path or (
                            external_data_target_key is not None
                            and external_data_target_key in hashed_stream_source_hashes_by_target
                        )
                        external_data_already_hashed = (
                            external_data_identity is not None
                            and (external_data_key, external_data_identity) in hashed_stream_file_instances
                        ) or (
                            external_data_target_key is not None
                            and external_data_target_key in hashed_stream_file_hashes_by_target
                        )
                        if external_data_identity is not None:
                            onnx_external_data_pre_scan_identities[onnx_external_data_path] = external_data_identity
                            external_data_instance = (external_data_key, external_data_identity)
                            if (
                                not external_data_was_stream_source
                                and external_data_instance not in counted_onnx_external_data_instances
                                and (
                                    external_data_target_key is None
                                    or external_data_target_key not in counted_onnx_external_data_targets
                                )
                            ):
                                onnx_external_data_bytes_scanned += _snapshot_file_size(external_data_identity)
                                counted_onnx_external_data_instances.add(external_data_instance)
                                if external_data_target_key is not None:
                                    counted_onnx_external_data_targets.add(external_data_target_key)
                        if not external_data_was_stream_source and not external_data_already_hashed:
                            if external_data_identity is None:
                                aggregate_hash_complete = False
                                continue
                            external_data_size = _snapshot_file_size(external_data_identity)
                            if max_total_size > 0 and top_level_hashed_bytes + external_data_size > max_total_size:
                                aggregate_hash_complete = False
                                continue
                        external_data_hash = None
                        if not defer_hash_for_file_backed_onnx:
                            external_data_hash = append_streamed_file_hash(
                                onnx_external_data_path,
                                scan_config,
                                progress_label=onnx_external_data_path.name,
                                skip_if_stream_source_seen=True,
                                skip_if_stream_target_seen=True,
                            )
                        if external_data_target_key is not None and (
                            defer_hash_for_file_backed_onnx or external_data_hash is not None
                        ):
                            consumed_onnx_external_data_aliases[external_data_key] = external_data_target_key

                # Scan the file
                if progress_callback:
                    progress_callback(f"Scanning {source_path.name}", (files_processed / (files_processed + 1)) * 100)

                if preflight_scan_result is not None:
                    scan_result = preflight_scan_result
                else:
                    with _trusted_logical_scan_path(str(scan_path), str(logical_source_path)):
                        scan_result = scan_file(
                            str(scan_path),
                            config=scan_config,
                        )
                if source_path.name.lower().endswith(SAFETENSORS_INDEX_SUFFIX):
                    structural_index_classification, structural_index_identity = classify_structural_safetensors_index(
                        source_path
                    )
                    structural_index_classification_complete = True
                content_routed_safetensors_index_payload = bool(
                    source_path.name.lower().endswith(SAFETENSORS_INDEX_SUFFIX)
                    and scan_result.scanner_name not in {None, "metadata", "safetensors", "scanner_selection"}
                    and structural_index_classification is False
                )
                if pinned_scan_context is not None:
                    _rebase_pinned_shard_result(scan_result, str(scan_path), report_path)
                    if pinned_local_alias or pinned_local_source:
                        _rebase_pinned_shard_result(
                            scan_result,
                            str(scan_path.parent),
                            str(logical_source_path.parent),
                        )
                        pinned_scan_parent = os.path.realpath(scan_path.parent)
                        _rebase_pinned_shard_result(
                            scan_result,
                            pinned_scan_parent,
                            str(logical_source_path.parent),
                        )
                    if (pinned_local_alias or pinned_local_source) and selected_resolved_path != str(scan_path):
                        _rebase_pinned_shard_result(scan_result, selected_resolved_path, report_path)
                if source_safetensors_shard_info is not None:
                    post_scan_safetensors_shard_info = ShardedModelDetector.detect_shards(
                        str(source_path),
                        index_search_root=stream_index_search_root,
                    )
                    if post_scan_safetensors_shard_info != source_safetensors_shard_info:
                        scan_result = _preserve_findings_with_shard_boundary_failure(
                            scan_result,
                            scan_result.scanner_name,
                            str(source_path),
                            {"path": str(source_path), "reason": "shard_family_changed_during_scan"},
                        )
                if suppress_consumed_onnx_external_data_accounting:
                    scan_result.bytes_scanned = 0
                openvino_sidecar_needs_independent_scan = (
                    preflight_scan_result is None
                    and openvino_scan_companion_path is not None
                    and _openvino_weights_sidecar_needs_independent_scan(
                        openvino_scan_companion_path,
                        scanner_selection,
                    )
                )
                if preflight_scan_result is None:
                    if not openvino_sidecar_needs_independent_scan:
                        scan_result.bytes_scanned += openvino_companion_bytes_scanned
                    scan_result.bytes_scanned += onnx_external_data_bytes_scanned
                if (
                    openvino_scan_companion_path is not None
                    and openvino_companion_pre_scan_identity is not None
                    and _snapshot_file_identity(openvino_scan_companion_path) != openvino_companion_pre_scan_identity
                ):
                    record_openvino_companion_stability_failure(
                        scan_path,
                        openvino_scan_companion_path,
                        "openvino_weights_changed_during_xml_scan",
                    )
                    preserve_shard_reconciliation_errors = True
                    aggregate_hash_complete = False
                if any(
                    _snapshot_file_identity(onnx_external_data_path) != pre_scan_identity
                    for onnx_external_data_path, pre_scan_identity in onnx_external_data_pre_scan_identities.items()
                ):
                    aggregate_hash_complete = False
                if openvino_sidecar_needs_independent_scan and openvino_scan_companion_path is not None:
                    independent_openvino_sidecar_path = openvino_scan_companion_path
                    independent_openvino_sidecar_result = scan_file(
                        str(openvino_scan_companion_path),
                        config=scan_config,
                    )
                if pre_scan_shard_target:
                    _ensure_streamed_shard_coverage_placeholder(scan_result, source_path)

                # Merge results
                if scan_result:
                    _normalize_unclassified_scan_failure(scan_result)
                    resolved_report_path = str(scan_path)
                    scanned_file_size = scan_path.stat().st_size
                    operational_scan_failure = _scan_result_has_operational_error(scan_result)
                    if operational_scan_failure:
                        preserve_shard_reconciliation_errors = True
                    post_scan_shard_target = _snapshot_validated_shard_target(
                        str(source_path),
                        resolved_path=selected_resolved_path,
                        family_group=shard_family_group,
                        family_group_policy="stream_staging",
                        trusted_root_marker=_trusted_shard_family_root,
                        authoritative_shard_index_base=authoritative_shard_index_base,
                        authoritative_shard_index_path=authoritative_shard_index_path,
                        authoritative_shard_index_fingerprint=authoritative_shard_index_fingerprint,
                        authoritative_shard_index_generation=authoritative_shard_index_generation,
                    )
                    stable_while_scanning = bool(
                        pre_scan_shard_target and pre_scan_shard_target == post_scan_shard_target
                    )
                    if pinned_scan_context is not None:
                        pinned_scan_context.__exit__(None, None, None)
                        pinned_scan_context = None
                    pinned_target_changed = bool(pinned_scan is not None and pinned_scan.changed_during_scan)
                    if (
                        pinned_local_alias
                        and not pinned_target_changed
                        and trusted_hf_alias_target is not None
                        and trusted_hf_alias_logical_path is not None
                        and (not delete_after_scan or preserve_source_after_scan)
                    ):
                        terminal_hf_alias_targets[Path(trusted_hf_alias_logical_path)] = dict(trusted_hf_alias_target)
                    if (
                        (pinned_local_alias or pinned_local_source)
                        and not pinned_target_changed
                        and is_hf_cache
                        and (not delete_after_scan or preserve_source_after_scan)
                    ):
                        for relative_name, companion_alias_path in pinned_local_alias_companion_paths.items():
                            companion_target_entry = pinned_companion_targets.get(relative_name)
                            if companion_target_entry is not None and companion_alias_path.is_symlink():
                                terminal_hf_alias_targets[companion_alias_path] = dict(companion_target_entry[1])
                    if (pinned_local_alias or pinned_local_source) and not pinned_target_changed:
                        for original_companion_path in pinned_local_alias_companion_paths.values():
                            for companion_root in (
                                Path(os.path.abspath(local_source_report_root))
                                if local_source_report_root is not None
                                else None,
                                Path(os.path.abspath(base_dir)) if base_dir is not None else None,
                            ):
                                if companion_root is None:
                                    continue
                                try:
                                    companion_relative_parts = (
                                        Path(os.path.abspath(original_companion_path)).relative_to(companion_root).parts
                                    )
                                except ValueError:
                                    continue
                                if companion_relative_parts in initial_local_source_entries:
                                    observed_local_source_artifacts.add(companion_relative_parts)
                                break
                            original_companion_key = Path(os.path.abspath(original_companion_path))
                            original_companion_identity = _snapshot_file_identity(original_companion_path)
                            original_companion_target = _file_target_identity_key(
                                original_companion_path,
                                original_companion_identity,
                            )
                            if original_companion_target is not None:
                                consumed_onnx_external_data_aliases[original_companion_key] = original_companion_target
                    if (pinned_local_alias or pinned_local_source) and pinned_target_changed:
                        scan_result.merge(_local_source_boundary_failure_scan_result(report_path))
                        operational_scan_failure = True
                        preserve_shard_reconciliation_errors = True
                        aggregate_hash_complete = False
                    final_shard_target = _snapshot_validated_shard_target(
                        str(source_path),
                        resolved_path=selected_resolved_path,
                        family_group=shard_family_group,
                        family_group_policy="stream_staging",
                        trusted_root_marker=_trusted_shard_family_root,
                        authoritative_shard_index_base=authoritative_shard_index_base,
                        authoritative_shard_index_path=authoritative_shard_index_path,
                        authoritative_shard_index_fingerprint=authoritative_shard_index_fingerprint,
                        authoritative_shard_index_generation=authoritative_shard_index_generation,
                    )
                    stable_after_unpinning = False
                    if not pinned_target_changed and initial_shard_target and final_shard_target:
                        initial_target = next(iter(initial_shard_target.values()))
                        final_target = next(iter(final_shard_target.values()))
                        stable_after_unpinning = all(
                            initial_target.get(field) == final_target.get(field)
                            for field in (
                                "resolved_path",
                                "device",
                                "inode",
                                "size",
                                "mtime_ns",
                                "ctime_ns",
                                "nlink",
                                "family_group",
                                "authoritative_shard_index_base",
                                "authoritative_shard_index_path",
                                "authoritative_shard_index_fingerprint",
                                "authoritative_shard_index_generation",
                            )
                        )
                    shard_target_stable = stable_while_scanning and stable_after_unpinning
                    if not operational_scan_failure and pre_scan_shard_target and not shard_target_stable:
                        scan_result = _preserve_findings_with_shard_boundary_failure(
                            scan_result,
                            scan_result.scanner_name,
                            str(source_path),
                            {"path": str(source_path), "reason": "shard_target_changed_during_scan"},
                        )
                        operational_scan_failure = True
                        preserve_shard_reconciliation_errors = True
                        aggregate_hash_complete = False
                    elif not operational_scan_failure and shard_target_stable:
                        validated_shard_targets.update(final_shard_target)

                    metadata_dict = dict(scan_result.metadata or {})
                    metadata_dict.setdefault("file_size", scanned_file_size)
                    if report_path != resolved_report_path:
                        metadata_dict.setdefault("source_path", report_path)
                        metadata_dict.setdefault("resolved_path", selected_resolved_path)

                    if file_hash is not None:
                        existing_hashes = metadata_dict.get("file_hashes")
                        if isinstance(existing_hashes, dict):
                            metadata_dict["file_hashes"] = {**existing_hashes, "sha256": file_hash}
                        else:
                            metadata_dict["file_hashes"] = {"sha256": file_hash}

                    # Use dict-based aggregation to avoid import issues
                    scan_result_dict = {
                        "bytes_scanned": adjusted_streamed_bytes(
                            scan_result.bytes_scanned,
                            source_bytes_preaccounted,
                        ),
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
                        asset["is_streamed"] = True
                        results.assets.extend(convert_assets_to_models([asset]))

                if independent_openvino_sidecar_result is not None and independent_openvino_sidecar_path is not None:
                    _normalize_unclassified_scan_failure(independent_openvino_sidecar_result)
                    operational_scan_failure = _scan_result_has_operational_error(independent_openvino_sidecar_result)
                    if operational_scan_failure:
                        preserve_shard_reconciliation_errors = True
                    sidecar_report_path = str(independent_openvino_sidecar_path)
                    sidecar_metadata = dict(independent_openvino_sidecar_result.metadata or {})
                    sidecar_metadata.setdefault("file_size", independent_openvino_sidecar_path.stat().st_size)
                    results.aggregate_scan_result(
                        {
                            "bytes_scanned": independent_openvino_sidecar_result.bytes_scanned,
                            "files_scanned": 1,
                            "has_errors": operational_scan_failure,
                            "success": independent_openvino_sidecar_result.success,
                            "issues": _serialize_streamed_records(
                                list(independent_openvino_sidecar_result.issues or []),
                                sidecar_report_path,
                                sidecar_report_path,
                            ),
                            "checks": _serialize_streamed_records(
                                list(independent_openvino_sidecar_result.checks or []),
                                sidecar_report_path,
                                sidecar_report_path,
                            ),
                            "scanners": (
                                [independent_openvino_sidecar_result.scanner_name]
                                if independent_openvino_sidecar_result.scanner_name
                                else []
                            ),
                            "file_metadata": {sidecar_report_path: sidecar_metadata},
                        }
                    )
                    asset = asset_from_scan_result(
                        sidecar_report_path,
                        independent_openvino_sidecar_result,
                        metadata=sidecar_metadata,
                    )
                    if asset:
                        asset["is_streamed"] = True
                        results.assets.extend(convert_assets_to_models([asset]))

                files_processed += 1
                if record_max_total_size_failure(report_path):
                    break

            except Exception as e:
                logger.error(f"Error processing {source_path}: {e}", exc_info=True)
                results.has_errors = True
                preserve_shard_reconciliation_errors = True
                aggregate_hash_complete = False
                if isinstance(e, _LocalSourceBoundaryError):
                    _record_local_source_boundary_failure(results, report_path)

            finally:
                if pinned_scan_context is not None:
                    pinned_scan_context.__exit__(None, None, None)
                # Delete file after scanning if requested
                if not preserve_source_after_scan:
                    delete_streamed_source(
                        source_path,
                        "after scanning",
                        defer_safetensors_index=not content_routed_safetensors_index_payload,
                        track_safetensors_index_candidate=not content_routed_safetensors_index_payload,
                        structural_index_classification=structural_index_classification,
                        structural_index_identity=structural_index_identity,
                        expected_content_hash=file_hash,
                        structural_index_classification_complete=structural_index_classification_complete,
                        quarantine_proven_non_index=content_routed_safetensors_index_payload,
                    )
                if openvino_scan_companion_path is not None and openvino_scan_companion_key is not None:
                    delete_streamed_source(openvino_scan_companion_path, "after OpenVINO XML scan")
                    consumed_openvino_companions.add(openvino_scan_companion_key)
                    deferred_openvino_sidecars.pop(openvino_scan_companion_key, None)
                    preserved_openvino_companion_snapshots.pop(openvino_scan_companion_key, None)

        # Source-owned cleanup may mutate retained artifacts. Run it before the
        # final authority proof and leave the outer finally as an exception fallback.
        close_streaming_generator()

        deferred_local_namespace_validation = bool(delete_after_scan and deferred_streamed_index_deletions)
        if local_source_initial_namespace is not None and base_dir is not None:
            for validated_target in validated_shard_targets.values():
                authoritative_index_path = validated_target.get("authoritative_shard_index_path")
                if not isinstance(authoritative_index_path, str):
                    continue
                authority_paths = [Path(authoritative_index_path)]
                with suppress(OSError, RuntimeError):
                    resolved_authority_path = authority_paths[0].resolve(strict=True)
                    if resolved_authority_path != authority_paths[0]:
                        authority_paths.append(resolved_authority_path)
                for authority_path in authority_paths:
                    for source_root in (base_dir, Path(local_source_report_root or base_dir)):
                        try:
                            authority_relative = Path(os.path.abspath(authority_path)).relative_to(
                                Path(os.path.abspath(source_root))
                            )
                        except ValueError:
                            continue
                        if authority_relative.parts in initial_local_source_entries:
                            observed_local_source_artifacts.add(authority_relative.parts)
                        break

        def record_terminal_local_namespace_failure() -> None:
            nonlocal preserve_shard_reconciliation_errors, aggregate_hash_complete
            _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
            preserve_shard_reconciliation_errors = True
            aggregate_hash_complete = False

        def deleted_local_source_relative_parts() -> set[tuple[str, ...]]:
            if base_dir is None:
                return set()
            deleted_relative_parts: set[tuple[str, ...]] = set()
            for deleted_source in deleted_streamed_sources:
                for source_root in (base_dir, Path(local_source_report_root or base_dir)):
                    try:
                        deleted_relative = Path(os.path.abspath(deleted_source)).relative_to(
                            Path(os.path.abspath(source_root))
                        )
                    except ValueError:
                        continue
                    deleted_relative_parts.add(deleted_relative.parts)
                    break
            return deleted_relative_parts

        def validate_terminal_local_namespace() -> None:
            if local_source_initial_namespace is None or base_dir is None:
                return
            expected_artifacts = {
                entry.relative_parts for entry in local_source_initial_namespace if entry.entry_type in {"file", "link"}
            }
            namespace_changed = not expected_artifacts.issubset(observed_local_source_artifacts)
            try:
                terminal_namespace = _capture_directory_owner_namespace(
                    base_dir,
                    None,
                    deadline=start_time + timeout,
                    max_entries=local_source_snapshot_max_entries,
                    trusted_root_symlink=bound_local_source_path is not None,
                )
            except (OSError, RuntimeError, TimeoutError):
                namespace_changed = True
            else:
                namespace_changed = namespace_changed or _terminal_local_namespace_changed(
                    local_source_initial_namespace,
                    terminal_namespace,
                    deleted_relative_parts=(deleted_local_source_relative_parts() if delete_after_scan else set()),
                )
            if namespace_changed:
                record_terminal_local_namespace_failure()

        if not deferred_local_namespace_validation:
            validate_terminal_local_namespace()

        if local_source_bound_guard is not None and local_source_bound_guard.changed(
            allow_directory_content_changes=delete_after_scan or local_source_namespace_was_extended,
        ):
            _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
            preserve_shard_reconciliation_errors = True
            aggregate_hash_complete = False
        if (
            local_source_bound_guard is None
            and expected_local_source_receipt is not None
            and not _local_source_receipts_match(
                expected_local_source_receipt,
                (
                    _snapshot_local_source_receipt(local_source_report_root)
                    if local_source_report_root is not None
                    else None
                ),
            )
        ):
            _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
            preserve_shard_reconciliation_errors = True
            aggregate_hash_complete = False

        for alias_path, expected_target in terminal_hf_alias_targets.items():
            try:
                resolved_alias = alias_path.resolve(strict=True)
                current_target_stat = os.stat(resolved_alias, follow_symlinks=False)
                expected_resolved_path = expected_target.get("resolved_path")
                alias_stable = isinstance(expected_resolved_path, str) and os.path.normcase(
                    os.path.normpath(str(resolved_alias))
                ) == os.path.normcase(os.path.normpath(expected_resolved_path))
                alias_stable = alias_stable and _validated_stat_matches_target(
                    current_target_stat,
                    expected_target,
                )
            except (OSError, RuntimeError):
                alias_stable = False
            if not alias_stable:
                record_terminal_local_namespace_failure()
                break

        for guard_fd, guarded_source, guarded_target in stream_windows_shard_guards:
            if not _windows_shard_guard_is_stable(guard_fd, guarded_target):
                record_terminal_shard_boundary_failure(guarded_source, "shard_target_changed_after_scan")

        def revalidate_terminal_streamed_shards(*, force_content_revalidation: bool) -> None:
            search_root = stream_index_search_root
            if search_root is None and validated_shard_targets:
                first_source = next(iter(validated_shard_targets))
                search_root = str(Path(first_source).absolute().parent)
            if search_root is None:
                return
            failures = _terminal_safetensors_shard_boundary_failures(
                validated_shard_targets,
                index_search_root=search_root,
                index_inspection_context=index_inspection_context,
                deleted_paths=deleted_streamed_sources,
                force_content_revalidation=force_content_revalidation,
            )
            for source_path, reason in failures.items():
                record_terminal_shard_boundary_failure(source_path, reason)

        # Promote a complete late index proof before reconciliation consumes
        # the family metadata, then revalidate once more to close the final
        # proof-to-reconciliation swap window.
        revalidate_terminal_streamed_shards(force_content_revalidation=False)
        _reconcile_cross_directory_shard_coverage(
            results,
            validated_shard_targets,
            missing_shard_errors_only=not preserve_shard_reconciliation_errors,
        )
        revalidate_terminal_streamed_shards(force_content_revalidation=True)
        delete_deferred_streamed_indexes("after terminal SafeTensors authority validation")

        if deferred_local_namespace_validation:
            validate_terminal_local_namespace()

        # Compute aggregate hash from all file hashes
        if file_hashes and aggregate_hash_complete:
            results.content_hash = compute_aggregate_hash(file_hashes)
            logger.info(f"Computed aggregate content hash: {results.content_hash}")

        # Finalize statistics
        results.finalize_statistics()
        results.success = not _results_should_be_unsuccessful(results)

    except _LocalSourceBoundaryError as e:
        logger.error(f"Streaming scan failed: {e}")
        results.has_errors = True
        results.success = False
        aggregate_hash_complete = False
        preserve_shard_reconciliation_errors = True
        _record_local_source_boundary_failure(results, local_source_report_root or "<local-stream>")
        results.finalize_statistics()
    except Exception as e:
        logger.error(f"Streaming scan failed: {e}")
        results.has_errors = True
        raise
    finally:
        close_streaming_generator()
        delete_deferred_streamed_indexes("during streaming cleanup")
        _close_windows_shard_guards(stream_windows_shard_guards)
        _deactivate_safetensors_index_inspection_context(index_context_token)
        for source_path, delete_error in pending_delete_failures.items():
            if not (source_path.exists() or source_path.is_symlink()):
                continue
            results.has_errors = True
            results.success = False
            _add_issue_to_model(
                results,
                f"Failed to delete streamed source {source_path}: {delete_error}",
                severity=IssueSeverity.INFO.value,
                location=str(source_path),
                details={
                    "analysis_incomplete": True,
                    "operational_error": True,
                    "exception_type": type(delete_error).__name__,
                },
            )
        try:
            if (
                bound_local_source_path is not None
                and resolved_local_source_path is not None
                and local_source_report_root is not None
            ):
                results = _rebase_local_source_result(
                    results,
                    bound_local_source_path,
                    resolved_local_source_path,
                    local_source_report_root,
                )
                if (
                    bound_local_source_is_lexical_link
                    and expected_local_source_receipt is not None
                    and expected_local_source_receipt.get("mode_type") == stat.S_IFDIR
                ):
                    results = _rebase_symlinked_local_source_directory_descendants(
                        results,
                        local_source_report_root,
                        resolved_local_source_path,
                    )
        finally:
            local_source_boundary_stack.close()

    return results
