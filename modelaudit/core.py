"""Core scanning engine for orchestrating model file security analysis."""

import hashlib
import itertools
import logging
import os
import stat
import tempfile
import time
from collections.abc import Iterator
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
from modelaudit.scanner_results import Check, Issue, IssueSeverity, ScanResult
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
from modelaudit.scanners.base import FORMAT_VALIDATION_CONFIG_KEY, BaseScanner
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
    TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT,
    XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
    XML_MODEL_INCONCLUSIVE_FORMAT,
    detect_file_format,
    detect_file_format_from_magic,
    detect_flax_msgpack_overlap_routes,
    detect_format_from_extension,
    detect_mxnet_symbol_content_route,
    detect_pytorch_binary_supplemental_format,
    detect_xgboost_ubjson_content_route,
    gzip_tar_trailing_data_status,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
    should_defer_safetensors_header_limit_hash,
    validate_file_type_with_formats,
)
from modelaudit.utils.file.handlers import (
    _SHARD_ALREADY_PINNED_CONFIG_KEY,
    MAX_RECORDED_MISSING_SHARD_INDICES,
    ShardedModelDetector,
    ValidatedShardTargets,
    _pinned_shard_scan_path,
    _ShardPinUnavailableError,
    scan_advanced_large_file,
    should_use_advanced_handler,
)
from modelaudit.utils.file.hdf5 import find_hdf5_signature_offset
from modelaudit.utils.file.large_file_handler import (
    scan_large_file,
    should_use_large_file_handler,
)
from modelaudit.utils.file.streaming import stream_analyze_file, stream_source_path
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

_add_asset_to_results = core_results.add_asset_to_results
_add_error_asset_to_results = core_results.add_error_asset_to_results
_DIRECTORY_PRECOUNT_CHILD_LIMIT = 1000
_COMPRESSED_TAR_STREAM_INCOMPLETE_REASON = "tar_compressed_stream_incomplete"


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
_metadata_has_incomplete_coverage = core_results.metadata_has_incomplete_coverage
_results_have_operational_error = core_results.results_have_operational_error
_results_should_be_unsuccessful = core_results.results_should_be_unsuccessful
_scan_result_has_operational_error = core_results.scan_result_has_operational_error
_serialize_streamed_records = core_results.serialize_streamed_records
_to_telemetry_severity = core_results.to_telemetry_severity
_normalize_unclassified_scan_failure = core_results.normalize_unclassified_scan_failure
determine_exit_code = core_results.determine_exit_code
merge_scan_result = core_results.merge_scan_result

HEADER_FORMAT_TO_SCANNER_ID = _registry.get_header_format_to_scanner_ids()


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
    scan_metadata["has_operational_errors"] = True
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

    def is_covered(target: Path) -> bool:
        target_str = str(target)
        if target.is_file():
            return target_str in directory_walk_covered_paths
        if not target.is_dir() or target_str not in directory_walk_covered_directories:
            return False

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
                if skip_file_types and should_skip_file(
                    file_path,
                    metadata_scanner_available=metadata_scanner_available,
                    scanner_selection_extensions=scanner_selection_extensions,
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
_RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON = "recognized_format_scanner_unavailable"
_FORMAT_DETECTION_READ_FAILED_REASON = "format_detection_read_failed"
_XML_MODEL_ROUTING_INCOMPLETE_REASON = "xml_model_routing_incomplete"
_PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON = "protobuf_model_routing_incomplete"
_LLAMAFILE_ROUTING_INCOMPLETE_REASON = "llamafile_routing_incomplete"
_MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON = "mxnet_symbol_routing_incomplete"
_PICKLE_ROUTING_INCOMPLETE_REASON = "pickle_routing_incomplete"
_DVC_SCAN_BUDGET_EXHAUSTED_REASON = "dvc_scan_budget_exhausted"
_DVC_DIRECTORY_WALK_FAILED_REASON = "dvc_directory_walk_failed"
_DVC_DIRECTORY_SYMLINK_UNSCANNED_REASON = "dvc_directory_symlink_unscanned"
_DVC_DIRECTORY_SPECIAL_FILE_UNSCANNED_REASON = "dvc_directory_special_file_unscanned"
_MAX_DVC_DIRECTORY_COVERAGE_GAPS = 100
_DVC_PARENT_FILE_CONFIG_KEY = "_dvc_parent_file"
_DVC_REMAINING_TOTAL_SIZE_CONFIG_KEY = "_dvc_remaining_total_size"
_DVC_TOTAL_SIZE_LIMIT_CONFIG_KEY = "_dvc_total_size_limit"
_DVC_EXCLUDED_PATHS_CONFIG_KEY = "_dvc_excluded_paths"
_DVC_COVERAGE_ROOTS_CONFIG_KEY = "_dvc_coverage_roots"
DVC_EXTERNAL_COVERED_PATHS_CONFIG_KEY = "_dvc_external_covered_paths"
DVC_EXTERNAL_COVERED_DIRECTORIES_CONFIG_KEY = "_dvc_external_covered_directories"


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


_XGBOOST_UBJSON_ROUTING_INCOMPLETE_REASON = "xgboost_ubjson_routing_incomplete"
_ONNX_ROUTING_INCOMPLETE_REASON = "onnx_routing_incomplete"
_TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON = "tensorflow_protobuf_routing_incomplete"
_ShardFamilyKey = tuple[str, str, int | None]
_ScanEntry = tuple[str, list[str], _ShardFamilyKey | None]
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
    return {str(source.absolute()): target}


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
    return scopes


def _complete_validated_shard_family_sources(validated_targets: ValidatedShardTargets) -> set[str]:
    """Return source paths belonging to complete, uniquely targeted shard families."""
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
            or expected_total <= 1
            or not 1 <= shard_index <= expected_total
        ):
            continue
        for family_scope in _validated_shard_family_scopes(source_path, target):
            grouped_targets.setdefault((pattern, expected_total, family_scope), {}).setdefault(shard_index, []).append(
                (source_path, target)
            )

    complete_sources: set[str] = set()
    for (_pattern, expected_total, _family_scope), targets_by_index in grouped_targets.items():
        # Indices are already bounded to [1, expected_total], so matching the
        # expected cardinality proves the complete range without materializing
        # an attacker-controlled range.
        if len(targets_by_index) != expected_total:
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
    if (
        not isinstance(shard_index, int)
        or not isinstance(expected_total, int)
        or expected_total <= 1
        or not 1 <= shard_index <= expected_total
    ):
        return

    missing_count = expected_total - 1
    missing_indices = list(
        itertools.islice(
            (index for index in range(1, expected_total + 1) if index != shard_index),
            MAX_RECORDED_MISSING_SHARD_INDICES,
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


def _remaining_shard_coverage_outcome(details: dict[str, Any]) -> tuple[str, str] | None:
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
    return None


def _update_missing_shard_coverage_record(record: Check | Issue, reason: str, message: str) -> None:
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
            existing_reason for existing_reason in existing_reasons if existing_reason != "missing_model_shards"
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
    if any(bool(metadata.get("operational_error")) for metadata in results.file_metadata.values()):
        return True
    if any(asset.type == "error" for asset in results.assets):
        return True
    records: list[Check | Issue] = [*results.checks, *results.issues]
    return any(isinstance(record.details, dict) and bool(record.details.get("operational_error")) for record in records)


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


def _reconcile_cross_directory_shard_coverage(
    results: ModelAuditResultModel,
    validated_targets: ValidatedShardTargets,
    *,
    missing_shard_errors_only: bool = False,
) -> bool:
    """Remove missing-shard outcomes, clearing errors only with explicit ownership proof."""
    complete_sources = _complete_validated_shard_family_sources(validated_targets)
    if not complete_sources:
        return False

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

    reconciled = False
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
        if (
            check.name == "Sharded Model Coverage Check"
            and details.get("scan_outcome_reason") == "missing_model_shards"
            and source_is_complete(check.location)
        ):
            reconciled = True
            replacement = _remaining_shard_coverage_outcome(details)
            if replacement is None:
                continue
            reason, message = replacement
            key = record_key(check, reason)
            if key in existing_check_reasons:
                continue
            _update_missing_shard_coverage_record(check, reason, message)
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
        if details.get("scan_outcome_reason") == "missing_model_shards" and source_is_complete(issue.location):
            reconciled = True
            replacement = _remaining_shard_coverage_outcome(details)
            if replacement is None:
                continue
            reason, message = replacement
            key = record_key(issue, reason)
            if key in existing_issue_reasons:
                continue
            _update_missing_shard_coverage_record(issue, reason, message)
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
        if not isinstance(reasons, list) or "missing_model_shards" not in reasons:
            continue
        remaining_reasons = [reason for reason in reasons if reason != "missing_model_shards"]
        if remaining_reasons:
            metadata["scan_outcome_reasons"] = remaining_reasons
            if metadata.get("scan_outcome_reason") == "missing_model_shards":
                metadata["scan_outcome_reason"] = remaining_reasons[0]
        else:
            metadata.pop("scan_outcome_reasons", None)
            if metadata.get("scan_outcome_reason") == "missing_model_shards":
                metadata.pop("scan_outcome_reason", None)
            if metadata.get("scan_outcome") == "inconclusive":
                metadata.pop("scan_outcome", None)
            metadata.pop("analysis_incomplete", None)
            metadata.pop("scan_outcome_message", None)
        results.file_metadata[source_path] = FileMetadataModel(**metadata)
        reconciled = True

    if reconciled:
        had_errors = results.has_errors
        results.has_errors = _results_have_explicit_operational_error(results) or (
            had_errors and (not missing_shard_errors_only or _results_have_retained_incomplete_outcome(results))
        )
        results.success = not _results_should_be_unsuccessful(results)
    return reconciled


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


def _allowed_hf_shard_alias_paths(shard_path: str, base_dir: Path, hf_cache_root: Path) -> list[str]:
    """Return shard siblings resolving inside the scan root or the same HF cache blobs directory."""
    allowed_paths: list[str] = []
    blobs_root = _trusted_hf_blobs_root(hf_cache_root)
    for candidate_path in Path(shard_path).parent.glob("*"):
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
    except (OSError, RuntimeError) as e:
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


def _select_non_hdf5_preferred_scanner_id(
    path: str,
    header_format: str,
    ext: str,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Select the trusted route that owns content before an HDF5 user block."""
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


def _should_defer_hash_for_safetensors_header_limit(file_path: str, config: dict[str, Any]) -> bool:
    """Avoid full-file hashing for terminal bounded outcomes from oversized SafeTensors framing."""
    try:
        max_header_bytes = int(config.get("max_safetensors_header_bytes", SAFETENSORS_MAX_HEADER_BYTES))
    except (TypeError, ValueError):
        return False
    return should_defer_safetensors_header_limit_hash(file_path, max_header_bytes)


def _should_defer_hash_for_max_file_size(file_path: str, config: dict[str, Any]) -> bool:
    """Avoid hashing files that regular scanning will reject on max_file_size."""
    try:
        max_file_size = int(config.get("max_file_size", 0) or 0)
    except (TypeError, ValueError):
        return False
    if max_file_size <= 0:
        return False

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


def _is_incomplete_aggregate_hash_placeholder(content_hash: str) -> bool:
    return content_hash.startswith(("unhashable_max_file_size_", "unhashable_max_total_size_"))


def _hash_files_by_path(
    file_paths: list[str],
    *,
    config: dict[str, Any] | None = None,
    routing_paths: dict[str, str] | None = None,
    hashed_identities: dict[str, dict[str, int]] | None = None,
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
    hashed_bytes = 0

    for file_path in file_paths:
        hash_config = config or {}
        routing_path = routing_paths.get(file_path, file_path) if routing_paths is not None else file_path
        if _should_defer_hash_for_safetensors_header_limit(routing_path, hash_config):
            content_hashes[file_path] = f"unhashable_bounded_safetensors_{id(file_path)}"
            continue
        if _should_defer_hash_for_max_file_size(routing_path, hash_config):
            content_hashes[file_path] = f"unhashable_max_file_size_{id(file_path)}"
            continue
        try:
            inode_key: tuple[int, int, int, int, int] | None = None
            pre_hash_stat: os.stat_result | None = None
            try:
                pre_hash_stat = os.stat(file_path, follow_symlinks=False)
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

            if _should_defer_hash_for_max_total_size(hash_config, hashed_bytes=hashed_bytes):
                content_hashes[file_path] = f"unhashable_max_total_size_{id(file_path)}"
                continue
            with suppress(OSError):
                hashed_bytes += os.path.getsize(file_path)
            content_hashes[file_path] = _calculate_file_hash(file_path)
            post_hash_stat = os.stat(file_path, follow_symlinks=False)
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
        file_attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def _resolve_directory_scan_target(
    file_path: Path,
    base_dir: Path,
    *,
    is_hf_cache: bool,
    hf_cache_root: Path | None,
    results: ModelAuditResultModel,
    reported_traversal_targets: set[str] | None = None,
) -> tuple[Path | None, bool, bool]:
    """Resolve a directory entry and reject symlink traversal outside the scan root."""
    is_symlink = file_path.is_symlink()
    try:
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
    if is_symlink and is_hf_cache and _path_has_part(file_path, "snapshots"):
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

    if not is_hf_cache_symlink and not is_within_directory(str(base_dir), str(resolved_file)):
        _add_path_traversal_issue_once(
            results,
            location=str(file_path),
            resolved_path=str(resolved_file),
            reported_targets=reported_traversal_targets,
        )
        return None, False, False

    return resolved_file, is_hf_cache_symlink, False


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
            # Directory scans require root traversal before scanner dispatch.
            # Single files must reach their owning scanner so unreadable model
            # inputs can produce a format-specific operational outcome.
            if not os.access(path, os.R_OK):
                raise PermissionError(f"Path is not readable: {path}")

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
            trusted_hf_blobs_root = _trusted_hf_blobs_root(hf_cache_root) if hf_cache_root is not None else None
            scanned_paths: set[str] = set()
            directory_walk_covered_directories: set[str] = set()
            hf_shard_blob_paths: set[str] = set()
            reported_traversal_targets: set[str] = set()

            # First pass: collect all file paths that need scanning
            files_to_scan: list[str] = []
            shard_family_representatives: dict[_ShardFamilyKey, str] = {}
            shard_family_paths: dict[_ShardFamilyKey, set[str]] = {}
            shard_family_targets: dict[_ShardFamilyKey, ValidatedShardTargets] = {}
            complete_hf_shard_families: set[_ShardFamilyKey] = set()
            dvc_directory_output_owners: list[tuple[Path, str]] = []
            pending_dvc_output_limit_checks: list[tuple[str, DvcResolution]] = []
            directory_coverage_gaps: dict[tuple[str, str], set[str]] = {}

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

            directory_discovery_started_at = _start_phase_timing(phase_timings)
            for root, dirs, files in os.walk(
                path,
                followlinks=False,
                onerror=collect_dvc_directory_walk_error,
            ):
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
                    if (
                        not file_path_obj.is_file()
                        and not file_path_obj.is_symlink()
                        and record_dvc_directory_special_file(file_path_obj)
                    ):
                        continue
                    resolved_file = resolve_covered_dvc_file_symlink(file_path_obj)
                    is_dvc_covered_file_symlink = resolved_file is not None
                    is_hf_cache_symlink = False
                    if resolved_file is None:
                        resolved_file, is_hf_cache_symlink, entry_unavailable = _resolve_directory_scan_target(
                            file_path_obj,
                            base_dir,
                            is_hf_cache=is_hf_cache,
                            hf_cache_root=hf_cache_root,
                            results=results,
                            reported_traversal_targets=reported_traversal_targets,
                        )
                        if entry_unavailable:
                            scan_metadata["success"] = False
                            scan_metadata["has_operational_errors"] = True
                    record_uncovered_dvc_file_symlink(file_path_obj, resolved_file)
                    if resolved_file is None:
                        continue
                    if not resolved_file.is_file() and record_dvc_directory_special_file(file_path_obj):
                        continue
                    snapshot_path = Path(file_path).absolute()
                    snapshot_shard_family_key = _shard_family_key_for_path(str(snapshot_path))
                    route_hf_shard_alias = (
                        is_hf_cache_symlink and resolved_file.exists() and snapshot_shard_family_key is not None
                    )
                    scan_source = snapshot_path if route_hf_shard_alias else resolved_file

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
                        shard_family_key = _shard_family_key_for_path(target_str)
                        is_hf_shard_alias = route_hf_shard_alias and target_path == scan_source
                        exclusion_path = (
                            str(resolved_file) if is_hf_shard_alias else _resolve_or_absolute_path(target_str)
                        )
                        if exclusion_path in dvc_excluded_paths:
                            continue
                        if is_hf_shard_alias:
                            hf_shard_blob_paths.add(str(resolved_file))
                        dedupe_target_str = (
                            str(resolved_file)
                            if is_hf_cache_symlink and target_path == scan_source and shard_family_key is None
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
                            if shard_family_key not in shard_family_representatives:
                                shard_family_representatives[shard_family_key] = target_str
                                family_paths = shard_family_paths.setdefault(shard_family_key, set())
                                shard_is_in_hf_snapshot = bool(
                                    is_hf_cache
                                    and hf_cache_root is not None
                                    and _path_has_part(Path(target_str), "snapshots")
                                )
                                allowed_hf_shard_paths = (
                                    _allowed_hf_shard_alias_paths(target_str, base_dir, hf_cache_root)
                                    if shard_is_in_hf_snapshot and hf_cache_root is not None
                                    else None
                                )
                                shard_info = ShardedModelDetector.detect_shards(
                                    target_str,
                                    allowed_paths=allowed_hf_shard_paths,
                                )
                                if shard_info is None:
                                    family_paths.add(target_str)
                                else:
                                    validated_targets: ValidatedShardTargets = {}
                                    detected_targets = shard_info.get("shard_targets")
                                    expected_total_shards = shard_info.get("expected_total_shards")
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
                                            family_paths.add(lexical_shard_path)
                                            validated_targets[lexical_shard_path] = {
                                                key: value
                                                for key, value in detected_target.items()
                                                if key
                                                in {"resolved_path", "device", "inode", "size", "mtime_ns", "ctime_ns"}
                                                and isinstance(value, (int, str))
                                            }
                                        else:
                                            _add_path_traversal_issue_once(
                                                results,
                                                location=shard_path,
                                                resolved_path=resolved_shard_path,
                                                reported_targets=reported_traversal_targets,
                                            )
                                    shard_family_targets[shard_family_key] = validated_targets
                                    incomplete_count_keys = (
                                        "missing_shard_count",
                                        "unreadable_shard_count",
                                        "out_of_scope_shard_count",
                                        "unvalidated_shard_count",
                                        "duplicate_shard_count",
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
            scan_entries: list[_ScanEntry] = [(file_path, [file_path], None) for file_path in files_to_scan]
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
                scan_entries.append((representative_file, ordered_family_paths, shard_family_key))

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

            # Second pass: scan every non-shard path independently and every shard
            # family once. Shard scans already expand to sibling shards in the
            # advanced handler, so scanning each shard path would duplicate work.
            if scan_entries:
                hash_sources: list[str] = []
                seen_hash_sources: set[str] = set()
                hash_source_by_path: dict[str, str] = {}
                for _representative_file, scanned_file_paths, entry_shard_family_key in scan_entries:
                    family_targets = (
                        shard_family_targets.get(entry_shard_family_key, {})
                        if entry_shard_family_key is not None
                        else {}
                    )
                    for scanned_file_path in scanned_file_paths:
                        hash_source = str(
                            family_targets.get(scanned_file_path, {}).get("resolved_path", scanned_file_path)
                        )
                        hash_source_by_path[scanned_file_path] = hash_source
                        if hash_source not in seen_hash_sources:
                            hash_sources.append(hash_source)
                            seen_hash_sources.add(hash_source)

                top_level_hashing_started_at = _start_phase_timing(phase_timings)
                routing_paths_by_source = {
                    hash_source: scanned_file_path for scanned_file_path, hash_source in hash_source_by_path.items()
                }
                hashed_identities_by_source: dict[str, dict[str, int]] = {}
                hashes_by_source = _hash_files_by_path(
                    hash_sources,
                    config=config,
                    routing_paths=routing_paths_by_source,
                    hashed_identities=hashed_identities_by_source,
                )
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
                _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)
                duplicate_paths_by_hash: dict[str, list[str]] = {}
                for file_path, content_hash in content_hashes.items():
                    if not content_hash.startswith("unhashable_"):
                        duplicate_paths_by_hash.setdefault(content_hash, []).append(file_path)
                recorded_content_hashes: set[str] = set()

                if len(scan_entries) > 1:
                    pickle_source_snapshot_stack.enter_context(shared_source_sensitive_caches())

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
                                        shard_family_targets.get(shard_family_key, {}),
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
                    }
                    scanned_dvc_paths.update(nested_scanned_paths)
                    internally_scanned_dvc_paths.update(nested_scanned_paths)
                    for root, _dirs, _files in os.walk(target, followlinks=False):
                        resolved_directory = str(Path(root).resolve())
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
                        if asset_path.is_file():
                            resolved_asset_path = str(asset_path.resolve())
                            scanned_dvc_paths.add(resolved_asset_path)
                            internally_scanned_dvc_paths.add(resolved_asset_path)
                    for root, _dirs, _files in os.walk(target, followlinks=False):
                        resolved_directory = str(Path(root).resolve())
                        dvc_scanned_directories.add(resolved_directory)
                        internally_scanned_dvc_directories.add(resolved_directory)
                    if _results_have_operational_error(nested_result):
                        scan_metadata["success"] = False
                        scan_metadata["has_operational_errors"] = True
                    results.content_hash = None
                    aggregate_hash_complete = False
                    continue

                results.files_scanned += 1

                # Hash the top-level target before scanning. Archive scanners merge
                # nested member results into their metadata, so scanner-emitted
                # hashes are not always the bytes of this target.
                defer_hash_for_max_total_size = _should_defer_hash_for_max_total_size(
                    config,
                    hashed_bytes=top_level_hashed_bytes,
                )
                defer_hash_for_max_file_size = _should_defer_hash_for_max_file_size(target, config)
                if defer_hash_for_max_total_size or defer_hash_for_max_file_size:
                    aggregate_hash_complete = False
                if (
                    not _should_defer_hash_for_safetensors_header_limit(target, config)
                    and not defer_hash_for_max_file_size
                    and not defer_hash_for_max_total_size
                ):
                    try:
                        top_level_hashing_started_at = _start_phase_timing(phase_timings)
                        with suppress(OSError):
                            top_level_hashed_bytes += os.path.getsize(target)
                        file_hash = _calculate_file_hash(target)
                        if not is_dvc_pointer or file_hash not in file_hashes:
                            file_hashes.append(file_hash)
                    except Exception as e:
                        logger.debug(f"Failed to hash file {target}: {e}")
                    finally:
                        _finish_phase_timing(phase_timings, "top_level_hashing", top_level_hashing_started_at)

                file_scan_started_at = _start_phase_timing(phase_timings)
                try:
                    file_result = scan_file(target, target_config)
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
                    scanned_dvc_paths.add(resolved_target)
                    internally_scanned_dvc_paths.add(resolved_target)
                    for check in file_result.checks:
                        shard_paths = check.details.get("shards") if isinstance(check.details, dict) else None
                        if check.name == "Sharded Model Detection" and isinstance(shard_paths, list):
                            resolved_shard_paths = {
                                str(Path(shard_path).resolve())
                                for shard_path in shard_paths
                                if isinstance(shard_path, str)
                            }
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

    except KeyboardInterrupt:
        logger.debug("Scan interrupted by user")
        scan_metadata["success"] = False
        _add_issue_to_model(
            results, "Scan interrupted by user", severity=IssueSeverity.INFO.value, details={"interrupted": True}
        )
    except Exception as e:
        report_path = _redacted_scan_path_for_reporting(path)
        report_error = _redacted_scan_error_for_reporting(e, path)
        if is_stream_url(path):
            logger.error(f"Error during scan: {report_error}")
        else:
            logger.exception(f"Error during scan: {report_error}")
        scan_metadata["success"] = False
        _add_issue_to_model(
            results,
            f"Error during scan: {report_error}",
            severity=IssueSeverity.INFO.value,
            details={"exception_type": type(e).__name__},
        )
        _add_error_asset_to_results(results, report_path)
    finally:
        pickle_source_snapshot_stack.close()

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
    from modelaudit.scanners.zip_scanner import ZipPreflightRejected, ZipScanner

    allowed_shard_paths = _allowed_shard_paths_from_config(config)
    allowed_shard_targets = _validated_shard_targets_from_config(config)
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

    # Check if we should use extreme handler BEFORE applying size limits
    # Extreme handler bypasses size limits for large models
    use_extreme_handler = should_use_advanced_handler(
        path,
        allowed_shard_paths=allowed_shard_paths,
        allowed_shard_targets=allowed_shard_targets,
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
        header_format = "unknown" if format_probe_error is not None else detect_file_format(path)
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
            magic_format = detect_file_format_from_magic(path)
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
    # Record telemetry for file type detection
    detected_format = header_format if header_format != "unknown" else ext_format
    record_file_type_detected(path, detected_format)

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
    if header_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT or magic_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT:
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
        logger.warning(discrepancy_msg)
    elif header_format != ext_format and header_format != "unknown" and ext_format != "unknown":
        # Suppress expected container-vs-extension differences for known wrapper formats.
        if not (
            (ext_format == "pytorch_binary" and header_format in ["zip", "pickle"] and ext == ".bin")
            or (ext_format == "pytorch_binary" and header_format == "pickle" and ext in [".pt", ".pth"])
            or (ext_format == "pickle" and header_format == "jax_checkpoint" and ext in [".ckpt", ".pickle"])
            or (ext_format == "keras" and header_format in ["zip", "hdf5"])
            or (ext_format == "protobuf" and header_format == "onnx" and ext == ".pb")
            or (ext_format == "skops" and header_format == "zip" and ext == ".skops")
        ):
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
                )  # Double timeout for extreme files
            elif use_large_handler:
                logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                result = scan_large_file(path, scanner, progress_callback, timeout)
            elif is_xgboost_pickle_spoof or (scanner_id == "nemo" and gzip_tar_trailing_status is not None):
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
        elif scanner_class is None:
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
                    )  # Double timeout for extreme files
                elif use_large_handler:
                    logger.debug(f"File size optimization: {path} ({file_size:,} bytes)")
                    result = scan_large_file(path, scanner, progress_callback, timeout)
                elif (
                    unavailable_preferred_scanner_id is not None
                    or is_xgboost_pickle_spoof
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
            if unavailable_preferred_scanner_id is None and scanner_selection.active:
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
            rule_code="S901" if not file_type_valid else None,
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
    shard_family_group: str | None = None,
    _trusted_shard_family_root: object | None = None,
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
    file_hashes: list[str] = []
    aggregate_hash_complete = True
    top_level_hashed_bytes = 0
    files_processed = 0
    skip_file_types: bool = bool(kwargs.get("skip_file_types", False))
    scan_kwargs = normalize_scanner_selection_config(kwargs)
    try:
        max_total_size = int(scan_kwargs.get("max_total_size", 0) or 0)
    except (TypeError, ValueError):
        max_total_size = 0
    scanner_selection = policy_from_config(scan_kwargs)
    scanner_selection_extensions = selected_scanner_extensions(scanner_selection) if scanner_selection.active else None
    if scanner_selection.active:
        results.scanner_selection = scanner_selection.to_metadata()
    metadata_scanner_available: bool = scanner_selection.allows("metadata") and _registry.has_scanner_class(
        "MetadataScanner"
    )
    nearby_license_cache: dict[str, list[str]] = {}
    pending_delete_failures: dict[Path, Exception] = {}
    validated_shard_targets: ValidatedShardTargets = {}
    preserve_shard_reconciliation_errors = False

    def delete_streamed_source(source_path: Path, context: str) -> None:
        if not delete_after_scan or not (source_path.exists() or source_path.is_symlink()):
            return
        try:
            source_path.unlink()
            logger.debug(f"Deleted {source_path} {context}")
        except Exception as e:
            logger.warning(f"Failed to delete {source_path} {context}: {e}")
            pending_delete_failures[source_path] = e

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

    base_dir = Path(scan_root).resolve() if scan_root is not None else None
    hf_cache_root = _find_hf_cache_root(base_dir) if base_dir is not None else None
    is_hf_cache = base_dir is not None and hf_cache_root is not None

    try:
        for file_path, _is_last in file_generator:
            source_path = Path(file_path)
            scan_path = source_path
            report_path = str(source_path)
            pinned_scan_context: Any | None = None

            # Check for interruption before starting work on the yielded file.
            try:
                check_interrupted()
            except KeyboardInterrupt:
                delete_streamed_source(source_path, "after streaming interruption")
                raise

            # Check timeout
            if time.time() - start_time > timeout:
                results.has_errors = True
                preserve_shard_reconciliation_errors = True
                aggregate_hash_complete = False
                logger.error(f"Streaming scan timeout after {timeout}s")
                delete_streamed_source(source_path, "after streaming timeout")
                break

            try:
                if is_hf_cache and _is_huggingface_cache_file(str(source_path)):
                    logger.debug(f"Skipping HuggingFace cache file: {source_path}")
                    continue

                if base_dir is not None:
                    resolved_path, _is_hf_cache_symlink, entry_unavailable = _resolve_directory_scan_target(
                        source_path,
                        base_dir,
                        is_hf_cache=is_hf_cache,
                        hf_cache_root=hf_cache_root,
                        results=results,
                    )
                    if entry_unavailable:
                        results.has_errors = True
                        preserve_shard_reconciliation_errors = True
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

                # Build config dict for scan_file
                scan_config = {
                    "timeout": timeout - int(time.time() - start_time),
                    **scan_kwargs,
                }
                initial_shard_target = _snapshot_validated_shard_target(
                    str(source_path),
                    resolved_path=str(scan_path),
                    family_group=shard_family_group,
                    family_group_policy="stream_staging",
                    trusted_root_marker=_trusted_shard_family_root,
                )
                selected_resolved_path = str(scan_path)
                pre_scan_shard_target: ValidatedShardTargets = {}
                if initial_shard_target:
                    initial_target = next(iter(initial_shard_target.values()))
                    resolved_target = initial_target.get("resolved_path")
                    if isinstance(resolved_target, str):
                        selected_resolved_path = resolved_target
                        try:
                            pinned_scan_context = _pinned_shard_scan_path(resolved_target, initial_target)
                            scan_path = Path(pinned_scan_context.__enter__().path)
                            pre_scan_shard_target = _snapshot_validated_shard_target(
                                str(source_path),
                                resolved_path=resolved_target,
                                family_group=shard_family_group,
                                family_group_policy="stream_staging",
                                trusted_root_marker=_trusted_shard_family_root,
                            )
                            scan_config[_SHARD_ALREADY_PINNED_CONFIG_KEY] = True
                        except _ShardPinUnavailableError as error:
                            if pinned_scan_context is not None:
                                pinned_scan_context = None
                            record_shard_pin_failure(source_path, error)
                            preserve_shard_reconciliation_errors = True
                            aggregate_hash_complete = False
                            files_processed += 1
                            continue

                file_hash: str | None = None
                defer_hash_for_max_total_size = _should_defer_hash_for_max_total_size(
                    scan_config,
                    hashed_bytes=top_level_hashed_bytes,
                )
                defer_hash_for_max_file_size = _should_defer_hash_for_max_file_size(str(scan_path), scan_config)
                if defer_hash_for_max_total_size or defer_hash_for_max_file_size:
                    aggregate_hash_complete = False
                if (
                    not _should_defer_hash_for_safetensors_header_limit(str(scan_path), scan_config)
                    and not defer_hash_for_max_file_size
                    and not defer_hash_for_max_total_size
                ):
                    if progress_callback:
                        progress_callback(
                            f"Hashing {source_path.name}",
                            (files_processed / (files_processed + 1)) * 100,
                        )
                    with suppress(OSError):
                        top_level_hashed_bytes += scan_path.stat().st_size
                    file_hash = compute_sha256_hash(scan_path)
                    file_hashes.append(file_hash)

                # Scan the file
                if progress_callback:
                    progress_callback(f"Scanning {source_path.name}", (files_processed / (files_processed + 1)) * 100)

                scan_result = scan_file(
                    str(scan_path),
                    config=scan_config,
                )
                if pre_scan_shard_target:
                    _ensure_streamed_shard_coverage_placeholder(scan_result, source_path)

                # Merge results
                if scan_result:
                    _normalize_unclassified_scan_failure(scan_result)
                    resolved_report_path = str(scan_path)
                    metadata_dict = dict(scan_result.metadata or {})
                    metadata_dict.setdefault("file_size", scan_path.stat().st_size)
                    if report_path != resolved_report_path:
                        metadata_dict.setdefault("source_path", report_path)
                        metadata_dict.setdefault("resolved_path", selected_resolved_path)
                    operational_scan_failure = _scan_result_has_operational_error(scan_result)
                    if operational_scan_failure:
                        preserve_shard_reconciliation_errors = True
                    post_scan_shard_target = _snapshot_validated_shard_target(
                        str(source_path),
                        resolved_path=selected_resolved_path,
                        family_group=shard_family_group,
                        family_group_policy="stream_staging",
                        trusted_root_marker=_trusted_shard_family_root,
                    )
                    stable_while_scanning = bool(
                        pre_scan_shard_target and pre_scan_shard_target == post_scan_shard_target
                    )
                    if pinned_scan_context is not None:
                        pinned_scan_context.__exit__(None, None, None)
                        pinned_scan_context = None
                    final_shard_target = _snapshot_validated_shard_target(
                        str(source_path),
                        resolved_path=selected_resolved_path,
                        family_group=shard_family_group,
                        family_group_policy="stream_staging",
                        trusted_root_marker=_trusted_shard_family_root,
                    )
                    stable_after_unpinning = False
                    if initial_shard_target and final_shard_target:
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
                                "nlink",
                                "family_group",
                            )
                        )
                    if not operational_scan_failure and stable_while_scanning and stable_after_unpinning:
                        validated_shard_targets.update(final_shard_target)

                    if file_hash is not None:
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
                        asset["is_streamed"] = True
                        results.assets.extend(convert_assets_to_models([asset]))

                files_processed += 1
                if max_total_size > 0 and results.bytes_scanned > max_total_size:
                    aggregate_hash_complete = False
                    _add_issue_to_model(
                        results,
                        f"Total scan size limit exceeded: {results.bytes_scanned} bytes (max: {max_total_size})",
                        severity=IssueSeverity.INFO.value,
                        location=report_path,
                        details={"max_total_size": max_total_size, "analysis_incomplete": True},
                    )
                    results.has_errors = True
                    preserve_shard_reconciliation_errors = True
                    break

            except Exception as e:
                logger.error(f"Error processing {source_path}: {e}", exc_info=True)
                results.has_errors = True
                preserve_shard_reconciliation_errors = True
                aggregate_hash_complete = False

            finally:
                if pinned_scan_context is not None:
                    pinned_scan_context.__exit__(None, None, None)
                # Delete file after scanning if requested
                delete_streamed_source(source_path, "after scanning")

        _reconcile_cross_directory_shard_coverage(
            results,
            validated_shard_targets,
            missing_shard_errors_only=not preserve_shard_reconciliation_errors,
        )

        # Compute aggregate hash from all file hashes
        if file_hashes and aggregate_hash_complete:
            results.content_hash = compute_aggregate_hash(file_hashes)
            logger.info(f"Computed aggregate content hash: {results.content_hash}")

        # Finalize statistics
        results.finalize_statistics()
        results.success = not _results_should_be_unsuccessful(results)

    except Exception as e:
        logger.error(f"Streaming scan failed: {e}")
        results.has_errors = True
        raise
    finally:
        close_generator = getattr(file_generator, "close", None)
        if callable(close_generator):
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

    return results
