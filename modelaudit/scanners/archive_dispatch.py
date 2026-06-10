"""Nested archive dispatch helpers used by recursive scanners."""

import json
import os
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

from ..core_results import mark_operational_scan_error
from ..scanner_registry_metadata import get_scanner_registry_metadata
from ..scanner_results import (
    SCAN_OUTCOME_REASONS_METADATA_KEY,
    Issue,
    IssueSeverity,
    ScanResult,
    mark_inconclusive_scan_result,
)
from ..scanner_selection import (
    SCANNER_SELECTION_PREFERRED_KIND,
    ScannerSelectionPolicy,
    add_scanner_selection_skip_check,
    allows_protobuf_model_candidate_analysis,
    allows_zip_content_analysis,
    allows_zip_structure_analysis,
    make_scanner_selection_skip_result,
    policy_from_config,
)
from ..utils.file.detection import (
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
    detect_mxnet_symbol_content_route,
    detect_pytorch_binary_supplemental_format,
    detect_xgboost_ubjson_content_route,
    has_inconclusive_renamed_flax_msgpack_routing,
    has_safetensors_gzip_nonmember_trailing_overlap,
    has_safetensors_routing_candidate,
    has_structural_torch7_content_route,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
)
from ..utils.file.hdf5 import HDF5_SIGNATURE_SCAN_MAX_BYTES, find_hdf5_signature_offset
from .base import FORMAT_VALIDATION_CONFIG_KEY
from .mxnet_scanner import MXNET_PREFERRED_XGBOOST_SKIP_PATH_CONFIG_KEY
from .xgboost_scanner import (
    XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY,
    XGBoostScanner,
    configure_content_routed_json_scan,
)

NESTED_SCAN_CALLBACK_CONFIG_KEY = "_archive_nested_scan_callback"
NestedScanCallback = Callable[[str, dict[str, Any] | None], ScanResult]


def _build_header_format_to_scanner_id() -> dict[str, str]:
    metadata = get_scanner_registry_metadata()
    header_format_to_scanner_id = {scanner_id: scanner_id for scanner_id in metadata}
    for scanner_id, scanner_info in metadata.items():
        for header_format in scanner_info.get("header_formats", ()):
            header_format_to_scanner_id[str(header_format)] = scanner_id
    return header_format_to_scanner_id


_HEADER_FORMAT_TO_SCANNER_ID: dict[str, str] = _build_header_format_to_scanner_id()
_COMPRESSED_HEADER_FORMATS: frozenset[str] = frozenset(
    header_format for header_format, scanner_id in _HEADER_FORMAT_TO_SCANNER_ID.items() if scanner_id == "compressed"
)
_R_SERIALIZED_EXTENSIONS: frozenset[str] = frozenset({".rds", ".rda", ".rdata"})
_RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON = "recognized_format_scanner_unavailable"
_XML_MODEL_ROUTING_INCOMPLETE_REASON = "xml_model_routing_incomplete"
_PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON = "protobuf_model_routing_incomplete"
_LLAMAFILE_ROUTING_INCOMPLETE_REASON = "llamafile_routing_incomplete"
_MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON = "mxnet_symbol_routing_incomplete"
_PICKLE_ROUTING_INCOMPLETE_REASON = "pickle_routing_incomplete"
_ONNX_ROUTING_INCOMPLETE_REASON = "onnx_routing_incomplete"
_TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON = "tensorflow_protobuf_routing_incomplete"
SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY = "_skip_composed_archive_member_scan"
KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY = "_known_unreadable_archive_entry_offsets"
_ZIP_CONTAINER_DISPATCHED_PATHS_PRIVATE_METADATA_KEY = "_zip_container_dispatched_paths"
_MAX_HDF5_USERBLOCK_ZIP_SEGMENTS = 16
_MAX_HDF5_USERBLOCK_ZIP_CANDIDATE_VALIDATIONS = 64
_MAX_HDF5_USERBLOCK_ZIP_VALIDATION_READ_BYTES = 32 * 1024 * 1024
_ZIP_LEADING_SIGNATURES: tuple[bytes, ...] = (
    b"PK\x03\x04",
    b"PK\x01\x02",
    b"PK\x05\x06",
    b"PK\x06\x06",
    b"PK\x06\x07",
    b"PK\x07\x08",
)


def _is_pickle_parse_only_overlap_issue(issue: Issue) -> bool:
    """Return whether a Pickle overlap issue is only parser fallout."""
    return (issue.rule_code == "S901" and issue.details.get("category") == "parse_error") or (
        issue.rule_code == "S902" and issue.details.get("notice_code") == "parse_incomplete"
    )


def _is_pickle_ignorable_flax_overlap_issue(issue: Issue) -> bool:
    """Return whether a Pickle issue is weak evidence inside a trusted Flax stream."""
    return _is_pickle_parse_only_overlap_issue(issue) or (
        issue.rule_code == "S902"
        and issue.details.get("pickle_rule_code") == "STRUCTURAL_TAMPER"
        and issue.details.get("tamper_type") == "oversized_frame"
    )


def _pickle_result_consumes_entire_payload(path: str, result: ScanResult) -> bool:
    """Return whether complete Pickle analysis proves no trailing Flax stream exists."""
    if (
        result.scanner_name != "pickle"
        or result.metadata.get("pickle_report_status") != "complete"
        or result.metadata.get("analysis_incomplete") is True
    ):
        return False

    coverage = result.metadata.get("pickle_coverage")
    if not isinstance(coverage, dict):
        return False
    if coverage.get("raw_scan_complete") is not True or coverage.get("opcode_scan_complete") is not True:
        return False

    positions = (
        result.metadata.get("first_pickle_end_pos"),
        coverage.get("bytes_scanned"),
        coverage.get("bytes_total"),
    )
    if any(not isinstance(position, int) or isinstance(position, bool) for position in positions):
        return False

    try:
        file_size = os.path.getsize(path)
    except OSError:
        return False
    return positions[0] == positions[1] == positions[2] == file_size


def _select_nested_scanner_id(
    path: str,
    header_format_override: str | None = None,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Select a scanner for extracted archive members using trusted file structure first."""
    header_format = header_format_override or detect_file_format(path)
    ext = os.path.splitext(path)[1].lower()

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

    if header_format == "tar" and ext == ".nemo":
        return "nemo"

    return _HEADER_FORMAT_TO_SCANNER_ID.get(header_format)


def _is_direct_header_route(scanner_id: str, header_format: str) -> bool:
    """Return whether the detected header directly maps to this scanner."""
    return header_format != "unknown" and _HEADER_FORMAT_TO_SCANNER_ID.get(header_format) == scanner_id


def _merge_pytorch_binary_supplemental_analysis(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    supplemental_scanner_id: str | None,
) -> None:
    """Merge strict nested `.bin` format analysis without dropping raw checks."""
    if supplemental_scanner_id is None:
        return

    from . import _registry

    scanner_selection = policy_from_config(config)
    if not scanner_selection.allows(supplemental_scanner_id):
        add_scanner_selection_skip_check(
            result,
            path,
            supplemental_scanner_id,
            scanner_selection,
            context="supplemental nested .bin content analysis",
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
        supplemental_config = dict(config or {})
        if supplemental_scanner_id == "executorch":
            from .executorch_scanner import PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY

            supplemental_config[PYTORCH_BINARY_PRIMARY_SCANNED_CONFIG_KEY] = True
        supplemental_result = scanner_class(config=supplemental_config).scan(path)

    primary_bytes_scanned = result.bytes_scanned
    result.merge(supplemental_result)
    result.bytes_scanned = max(primary_bytes_scanned, supplemental_result.bytes_scanned)
    result.metadata.setdefault("supplemental_scanners", []).append(supplemental_scanner_id)


def detect_safetensors_overlap_scanner_ids(path: str) -> frozenset[str]:
    """Return non-HDF5 scanners that own a validated SafeTensors overlap."""
    if not has_safetensors_routing_candidate(path):
        return frozenset()
    scanner_ids = {"safetensors"}
    hdf5_signature_offset = find_hdf5_signature_offset(path)
    try:
        if zipfile.is_zipfile(path):
            scanner_ids.add("zip")
    except OSError:
        pass
    if hdf5_signature_offset is not None:
        try:
            detected_format = detect_file_format(path)
        except OSError:
            detected_format = "unknown"
        detected_scanner_id = _HEADER_FORMAT_TO_SCANNER_ID.get(detected_format)
        if isinstance(detected_scanner_id, str) and detected_scanner_id != "keras_h5":
            scanner_ids.add(detected_scanner_id)
    if has_safetensors_gzip_nonmember_trailing_overlap(path):
        scanner_ids.add("compressed")
    if has_structural_torch7_content_route(path):
        scanner_ids.add("torch7")
    return frozenset(scanner_ids)


def merge_safetensors_overlap_analysis(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    scanner_selection: ScannerSelectionPolicy,
    scanner_ids: frozenset[str],
) -> None:
    """Merge every trusted owner of a validated SafeTensors overlap for this path."""
    from . import _registry

    pending_scanner_ids = set(scanner_ids - {result.scanner_name})
    dispatched_zip_paths = result._private_metadata.get(_ZIP_CONTAINER_DISPATCHED_PATHS_PRIVATE_METADATA_KEY, ())
    zip_already_dispatched = (
        isinstance(dispatched_zip_paths, list | tuple | set | frozenset)
        and os.path.realpath(path) in dispatched_zip_paths
    )
    if result.scanner_name == "zip" and "zip" in scanner_ids and not zip_already_dispatched:
        pending_scanner_ids.add("zip")

    for scanner_id in sorted(pending_scanner_ids):
        zip_analysis_allowed = scanner_id == "zip" and allows_zip_content_analysis(scanner_selection)
        if not zip_analysis_allowed and not scanner_selection.allows(scanner_id):
            add_scanner_selection_skip_check(
                result,
                path,
                scanner_id,
                scanner_selection,
                context="validated SafeTensors overlapping content analysis",
            )
            continue

        if scanner_id == "zip":
            supplemental_result = ScanResult(scanner_name="zip")
            merge_executable_zip_container_findings(
                path,
                supplemental_result,
                config,
                context="validated SafeTensors overlapping ZIP analysis",
            )
            supplemental_result.finish(success=not supplemental_result.has_errors)
        else:
            scanner_class = _registry.load_scanner_by_id(scanner_id)
            if scanner_class is None:
                supplemental_result = _make_unavailable_recognized_format_result(path, scanner_id, scanner_id)
            else:
                supplemental_config = config
                if scanner_id == "compressed":
                    from .compressed_scanner import ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY

                    supplemental_config = dict(config or {})
                    supplemental_config[ALLOW_SAFETENSORS_NONMEMBER_TRAILING_CONFIG_KEY] = True
                supplemental_result = scanner_class(config=supplemental_config).scan(path)

        primary_bytes_scanned = result.bytes_scanned
        result.merge(supplemental_result)
        result.bytes_scanned = max(primary_bytes_scanned, supplemental_result.bytes_scanned)
        if scanner_id != result.scanner_name:
            supplemental_scanners = result.metadata.setdefault("supplemental_scanners", [])
            if isinstance(supplemental_scanners, list) and scanner_id not in supplemental_scanners:
                supplemental_scanners.append(scanner_id)
        supplemental_scanners = result.metadata.get("supplemental_scanners")
        if isinstance(supplemental_scanners, list):
            result.metadata["supplemental_scanners"] = list(dict.fromkeys(supplemental_scanners))
        _deduplicate_exact_merged_findings(result)


def _nested_scanner_can_handle(
    scanner_class: type[Any],
    scanner_id: str,
    path: str,
    header_format_override: str | None = None,
) -> bool:
    """Honor trusted header routing even when temporary archive paths are suffix-gated."""
    if scanner_class.can_handle(path):
        return True

    if scanner_id == "zip":
        return False

    if not os.path.exists(path):
        return False

    try:
        header_format = header_format_override or detect_file_format(path)
    except Exception:
        return False

    return _is_direct_header_route(scanner_id, header_format)


def _make_unavailable_recognized_format_result(path: str, format_: str, scanner_id: str | None) -> ScanResult:
    """Fail closed when nested routing recognizes a format but no scanner can analyze it."""
    from . import _registry

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
    mark_inconclusive_scan_result(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
    mark_operational_scan_error(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_xml_model_result(path: str) -> ScanResult:
    """Fail closed when bounded nested XML routing cannot reach the structural root."""
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
    mark_inconclusive_scan_result(result, _XML_MODEL_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _XML_MODEL_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_protobuf_model_result(path: str) -> ScanResult:
    """Fail closed when a nested protobuf candidate cannot receive analysis."""
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
    mark_inconclusive_scan_result(result, _PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _deduplicate_exact_merged_findings(result: ScanResult) -> None:
    """Remove identical output emitted by composed subtype and ZIP analyses."""

    def signature(item: Any) -> str:
        payload = item.model_dump(mode="json", exclude={"timestamp"})
        return json.dumps(payload, sort_keys=True, default=str)

    seen_issues: set[str] = set()
    unique_issues = []
    for issue in result.issues:
        issue_signature = signature(issue)
        if issue_signature in seen_issues:
            continue
        seen_issues.add(issue_signature)
        unique_issues.append(issue)
    result.issues = unique_issues

    seen_checks: set[str] = set()
    unique_checks = []
    for check in result.checks:
        check_signature = signature(check)
        if check_signature in seen_checks:
            continue
        seen_checks.add(check_signature)
        unique_checks.append(check)
    result.checks = unique_checks


def _merge_composed_scan_result(result: ScanResult, other: ScanResult) -> None:
    """Merge analyses while retaining all incomplete-coverage reasons."""
    prior_reasons = result.metadata.get(SCAN_OUTCOME_REASONS_METADATA_KEY, [])
    additional_reasons = other.metadata.get(SCAN_OUTCOME_REASONS_METADATA_KEY, [])
    combined_reasons = list(
        dict.fromkeys(
            [
                *(prior_reasons if isinstance(prior_reasons, list) else []),
                *(additional_reasons if isinstance(additional_reasons, list) else []),
            ]
        )
    )
    primary_bytes_scanned = result.bytes_scanned
    result.merge(other)
    result.bytes_scanned = max(primary_bytes_scanned, other.bytes_scanned)
    if combined_reasons:
        result.metadata[SCAN_OUTCOME_REASONS_METADATA_KEY] = combined_reasons


def _mark_zip_container_dispatched(result: ScanResult, path: str) -> None:
    """Retain local ZIP dispatch ownership across nested result merges."""
    dispatched_paths = result._private_metadata.setdefault(_ZIP_CONTAINER_DISPATCHED_PATHS_PRIVATE_METADATA_KEY, [])
    if not isinstance(dispatched_paths, list):
        dispatched_paths = []
        result._private_metadata[_ZIP_CONTAINER_DISPATCHED_PATHS_PRIVATE_METADATA_KEY] = dispatched_paths
    normalized_path = os.path.realpath(path)
    if normalized_path not in dispatched_paths:
        dispatched_paths.append(normalized_path)


def merge_executable_zip_container_findings(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    *,
    context: str,
) -> None:
    """Merge all enabled subtype checks and one generic ZIP member traversal."""
    from . import _registry
    from .zip_scanner import ZipPreflightRejected, ZipScanner

    try:
        if not zipfile.is_zipfile(path):
            return
    except OSError:
        return

    _mark_zip_container_dispatched(result, path)

    scanner_selection = policy_from_config(config)
    ext = os.path.splitext(path)[1].lower()
    subtype_ids: list[str] = []
    try:
        if is_torchserve_mar_archive(path, config):
            subtype_ids.append("torchserve_mar")
        if is_keras_zip_archive(path, allow_config_only=ext == ".keras", config=config):
            subtype_ids.append("keras_zip")
        if is_pytorch_zip_archive(path, config):
            subtype_ids.append("pytorch_zip")
        if is_executorch_archive(path, config):
            subtype_ids.append("executorch")
        if is_skops_archive(path, config):
            subtype_ids.append("skops")
    except ZipPreflightRejected as exc:
        result.merge(exc.result)
        _mark_zip_container_dispatched(result, path)
        return

    subtype_config = dict(config or {})
    subtype_config[SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY] = True
    zip_config = dict(config or {})
    known_unreadable_offsets: set[int] = set()
    for subtype_id in subtype_ids:
        if scanner_selection.allows(subtype_id):
            subtype_scanner = _registry.load_scanner_by_id(subtype_id)
            if subtype_scanner is None:
                subtype_result = _make_unavailable_recognized_format_result(path, subtype_id, subtype_id)
            else:
                subtype_result = subtype_scanner(config=subtype_config).scan(path)
                raw_offsets = subtype_result.metadata.pop(KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY, ())
                if isinstance(raw_offsets, (list, tuple, set, frozenset)):
                    known_unreadable_offsets.update(
                        offset for offset in raw_offsets if isinstance(offset, int) and not isinstance(offset, bool)
                    )
            _merge_composed_scan_result(result, subtype_result)
        else:
            add_scanner_selection_skip_check(
                result,
                path,
                subtype_id,
                scanner_selection,
                context=f"{context} subtype analysis",
            )

    if scanner_selection.allows("zip"):
        if known_unreadable_offsets:
            zip_config[KNOWN_UNREADABLE_ARCHIVE_ENTRY_OFFSETS_CONFIG_KEY] = sorted(known_unreadable_offsets)
        _merge_composed_scan_result(result, ZipScanner(config=zip_config).scan_archive_members(path))
    else:
        add_scanner_selection_skip_check(
            result,
            path,
            "zip",
            scanner_selection,
            context=f"{context} ZIP member analysis",
        )

    _deduplicate_exact_merged_findings(result)
    _mark_zip_container_dispatched(result, path)


def merge_hdf5_userblock_zip_findings(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    signature_offset: int,
    *,
    context: str,
) -> None:
    """Merge ZIP findings from a complete HDF5 user block with a logical EOF."""
    temp_path: str | None = None
    try:
        eocd_offsets: list[int] = []
        saw_zip_record = False
        carry = b""
        bytes_read = 0
        scan_limit = min(signature_offset, HDF5_SIGNATURE_SCAN_MAX_BYTES)
        temp_suffix = Path(path).suffix or ".zip"
        with open(path, "rb") as source:
            remaining = scan_limit
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise OSError("HDF5 user block ended before its validated signature offset")
                candidate_bytes = carry + chunk
                candidate_base = bytes_read - len(carry)
                if (
                    b"PK\x03\x04" in candidate_bytes
                    or b"PK\x01\x02" in candidate_bytes
                    or (bytes_read == 0 and candidate_bytes.startswith(_ZIP_LEADING_SIGNATURES))
                ):
                    saw_zip_record = True
                search_offset = 0
                while True:
                    match_offset = candidate_bytes.find(b"PK\x05\x06", search_offset)
                    if match_offset < 0:
                        break
                    saw_zip_record = True
                    eocd_offsets.append(candidate_base + match_offset)
                    if len(eocd_offsets) > 4096:
                        raise OSError("HDF5 user block contains too many ZIP end-record candidates")
                    search_offset = match_offset + 1
                carry = candidate_bytes[-3:]
                bytes_read += len(chunk)
                remaining -= len(chunk)

        logical_zip_segments = _find_valid_zip_logical_segments(path, eocd_offsets, scan_limit)
        if not logical_zip_segments:
            if saw_zip_record:
                raise OSError("HDF5 user block has ZIP-like content without a valid ZIP end record")
            if scan_limit < signature_offset:
                _mark_hdf5_userblock_zip_probe_incomplete(result, path, signature_offset, scan_limit)
            return
        if len(logical_zip_segments) > _MAX_HDF5_USERBLOCK_ZIP_SEGMENTS:
            raise OSError("HDF5 user block contains too many complete ZIP segments")
        logical_zip_end = logical_zip_segments[-1][1]

        has_trailing_content = False
        with open(path, "rb") as source:
            source.seek(logical_zip_end)
            trailing_bytes = scan_limit - logical_zip_end
            while trailing_bytes > 0:
                chunk = source.read(min(1024 * 1024, trailing_bytes))
                if not chunk:
                    raise OSError("HDF5 user block ended before its validated signature offset")
                if chunk.rstrip(b"\x00"):
                    has_trailing_content = True
                trailing_bytes -= len(chunk)

        previous_top_level_end = 0
        for index, (archive_start, logical_end) in enumerate(logical_zip_segments):
            # Analyze nested candidates, but do not let their EOCDs advance the
            # boundary used to isolate independent concatenated archives.
            is_contained = any(
                containing_start <= archive_start for containing_start, _ in logical_zip_segments[index + 1 :]
            )
            if previous_top_level_end == 0:
                temp_path = _copy_file_prefix_to_temp(path, logical_end, temp_suffix)
            else:
                required_zero_prefix_length = 0
                if not is_contained:
                    required_zero_prefix_length = archive_start - previous_top_level_end
                temp_path = _copy_file_range_to_temp(
                    path,
                    previous_top_level_end,
                    logical_end,
                    temp_suffix,
                    required_zero_prefix_length=required_zero_prefix_length,
                )
            supplemental_result = ScanResult(scanner_name="zip")
            merge_executable_zip_container_findings(temp_path, supplemental_result, config, context=context)
            _replace_scan_result_path(supplemental_result, temp_path, path)
            _merge_composed_scan_result(result, supplemental_result)
            with suppress(OSError):
                os.unlink(temp_path)
            temp_path = None
            if not is_contained:
                previous_top_level_end = logical_end
        if has_trailing_content:
            reason = "hdf5_userblock_zip_trailing_content_unanalyzed"
            mark_inconclusive_scan_result(result, reason)
            result.add_check(
                name="HDF5 User Block Trailing Content",
                passed=False,
                message="Non-padding content after the ZIP end record could not be fully analyzed.",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": reason,
                    "hdf5_signature_offset": signature_offset,
                    "zip_logical_end": logical_zip_end,
                },
                rule_code="S902",
            )
            result.finish(success=False)
        if scan_limit < signature_offset:
            _mark_hdf5_userblock_zip_probe_incomplete(result, path, signature_offset, scan_limit)
        _deduplicate_exact_merged_findings(result)
    except OSError as exc:
        reason = "hdf5_userblock_zip_scan_failed"
        mark_inconclusive_scan_result(result, reason)
        result.add_check(
            name="HDF5 User Block ZIP Analysis",
            passed=False,
            message=f"Unable to scan ZIP content in the HDF5 user block: {exc}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
                "hdf5_signature_offset": signature_offset,
            },
            rule_code="S902",
        )
        result.finish(success=False)
    finally:
        if temp_path is not None:
            with suppress(OSError):
                os.unlink(temp_path)


def _mark_hdf5_userblock_zip_probe_incomplete(
    result: ScanResult,
    path: str,
    signature_offset: int,
    scanned_bytes: int,
) -> None:
    """Fail closed when bounded ZIP discovery cannot cover the full user block."""
    reason = "hdf5_userblock_zip_probe_incomplete"
    mark_inconclusive_scan_result(result, reason)
    result.add_check(
        name="HDF5 User Block ZIP Probe",
        passed=False,
        message="HDF5 user-block ZIP discovery reached its bounded scan limit.",
        severity=IssueSeverity.INFO,
        location=path,
        details={
            "analysis_incomplete": True,
            "scan_outcome_reason": reason,
            "hdf5_signature_offset": signature_offset,
            "zip_probe_bytes_scanned": scanned_bytes,
            "zip_probe_max_bytes": HDF5_SIGNATURE_SCAN_MAX_BYTES,
        },
        rule_code="S902",
    )
    result.finish(success=False)


def _replace_scan_result_path(result: ScanResult, old_path: str, new_path: str) -> None:
    """Replace a temporary archive path in user-visible supplemental evidence."""
    for issue in result.issues:
        if isinstance(issue.location, str):
            issue.location = issue.location.replace(old_path, new_path)
        issue.details = _replace_nested_path(issue.details, old_path, new_path)
    for check in result.checks:
        if isinstance(check.location, str):
            check.location = check.location.replace(old_path, new_path)
        check.details = _replace_nested_path(check.details, old_path, new_path)
    result.metadata = _replace_nested_path(result.metadata, old_path, new_path)


def _replace_nested_path(value: Any, old_path: str, new_path: str) -> Any:
    if isinstance(value, str):
        return value.replace(old_path, new_path)
    if isinstance(value, list):
        return [_replace_nested_path(item, old_path, new_path) for item in value]
    if isinstance(value, tuple):
        return tuple(_replace_nested_path(item, old_path, new_path) for item in value)
    if isinstance(value, dict):
        return {key: _replace_nested_path(item, old_path, new_path) for key, item in value.items()}
    return value


class _LogicalEOFReader:
    """Expose a bounded logical EOF for ZIP validation without copying again."""

    def __init__(self, handle: BinaryIO, logical_size: int, read_budget: list[int]) -> None:
        self._handle = handle
        self._logical_size = logical_size
        self._read_budget = read_budget

    def tell(self) -> int:
        return self._handle.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self._logical_size + offset
        else:
            raise ValueError(f"Unsupported seek mode: {whence}")
        if target < 0:
            raise OSError("Cannot seek before the bounded archive start")
        return self._handle.seek(min(target, self._logical_size), os.SEEK_SET)

    def read(self, size: int = -1) -> bytes:
        remaining = max(0, self._logical_size - self.tell())
        requested = remaining if size < 0 else min(size, remaining)
        if requested > self._read_budget[0]:
            raise OSError("HDF5 user-block ZIP validation read budget exhausted")
        data = self._handle.read(requested)
        self._read_budget[0] -= len(data)
        return data

    def seekable(self) -> bool:
        return True


def _find_valid_zip_logical_segments(
    temp_path: str,
    eocd_offsets: list[int],
    signature_offset: int,
) -> list[tuple[int, int]]:
    """Return archive starts and complete ZIP ends before the HDF5 signature."""
    if len(eocd_offsets) > _MAX_HDF5_USERBLOCK_ZIP_CANDIDATE_VALIDATIONS:
        raise OSError("HDF5 user block contains too many ZIP end-record candidates to validate safely")
    logical_segments: list[tuple[int, int]] = []
    read_budget = [_MAX_HDF5_USERBLOCK_ZIP_VALIDATION_READ_BYTES]
    with open(temp_path, "rb") as handle:
        for eocd_offset in eocd_offsets:
            handle.seek(eocd_offset)
            end_record = handle.read(22)
            if len(end_record) != 22:
                continue
            logical_end = eocd_offset + 22 + int.from_bytes(end_record[20:22], "little")
            if logical_end > signature_offset:
                continue
            bounded_reader = _LogicalEOFReader(handle, logical_end, read_budget)
            bounded_reader.seek(0)
            try:
                with zipfile.ZipFile(bounded_reader) as archive:
                    entries = archive.infolist()
                    archive_start = min(
                        (entry.header_offset for entry in entries),
                        default=archive.start_dir,
                    )
            except (OSError, zipfile.BadZipFile):
                continue
            if archive_start < 0 or archive_start > eocd_offset:
                continue
            segment = (archive_start, logical_end)
            if segment not in logical_segments:
                logical_segments.append(segment)
    return logical_segments


def _copy_file_prefix_to_temp(path: str, length: int, suffix: str) -> str:
    """Copy exactly one validated archive prefix to a temporary file."""
    temp_path: str | None = None
    try:
        with open(path, "rb") as source, tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            temp_path = temp_file.name
            remaining = length
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise OSError("HDF5 user-block ZIP ended before its validated logical EOF")
                temp_file.write(chunk)
                remaining -= len(chunk)
        return temp_path
    except BaseException:
        if temp_path is not None:
            with suppress(OSError):
                os.unlink(temp_path)
        raise


def _copy_file_range_to_temp(
    path: str,
    start: int,
    end: int,
    suffix: str,
    *,
    required_zero_prefix_length: int = 0,
) -> str:
    """Copy one validated concatenated ZIP segment to a temporary file."""
    range_length = end - start
    if not 0 <= required_zero_prefix_length <= range_length:
        raise OSError("HDF5 user-block ZIP padding exceeds the validated segment range")

    temp_path: str | None = None
    try:
        with open(path, "rb") as source, tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            source.seek(start)
            temp_path = temp_file.name
            remaining = range_length
            zero_prefix_remaining = required_zero_prefix_length
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise OSError("HDF5 user-block ZIP segment ended before its validated logical EOF")
                checked_length = min(len(chunk), zero_prefix_remaining)
                if chunk[:checked_length].rstrip(b"\x00"):
                    raise OSError("HDF5 user block contains non-padding content between ZIP segments")
                temp_file.write(chunk)
                remaining -= len(chunk)
                zero_prefix_remaining -= checked_length
        return temp_path
    except BaseException:
        if temp_path is not None:
            with suppress(OSError):
                os.unlink(temp_path)
        raise


def merge_flax_msgpack_overlap_findings(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    *,
    context: str,
    scanned_scanner_ids: frozenset[str] = frozenset(),
) -> None:
    """Preserve trusted foreign-format findings inside Flax-routed payloads."""
    from . import _registry

    scanner_selection = policy_from_config(config)
    for scanner_id in detect_flax_msgpack_overlap_routes(path, include_unvalidated_pickle=True):
        if scanner_id in scanned_scanner_ids:
            continue
        if scanner_selection.allows(scanner_id):
            scanner_class = _registry.load_scanner_by_id(scanner_id)
            if scanner_class is None:
                overlap_result = _make_unavailable_recognized_format_result(path, scanner_id, scanner_id)
            else:
                overlap_result = scanner_class(config=config).scan(path)
            # Binary-looking Flax prefixes may be invalid Pickle near-matches;
            # merge substantive findings, including structural-tamper S902.
            if (
                scanner_id == "pickle"
                and overlap_result.metadata.get("parsing_failed") is True
                and overlap_result.metadata.get("failure_reason") == "unknown_opcode_or_format_error"
                and not any(
                    issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
                    and not _is_pickle_ignorable_flax_overlap_issue(issue)
                    for issue in overlap_result.issues
                )
            ):
                continue
            _merge_composed_scan_result(result, overlap_result)
        else:
            add_scanner_selection_skip_check(
                result,
                path,
                scanner_id,
                scanner_selection,
                context=context,
            )
    _deduplicate_exact_merged_findings(result)


def merge_inconclusive_flax_msgpack_outcome(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    *,
    context: str,
) -> None:
    """Preserve ambiguous Flax coverage when a strict overlapping owner is primary."""
    from . import _registry

    if _pickle_result_consumes_entire_payload(path, result):
        return
    if result.scanner_name not in detect_flax_msgpack_overlap_routes(
        path
    ) or not has_inconclusive_renamed_flax_msgpack_routing(path):
        return

    scanner_selection = policy_from_config(config)
    if scanner_selection.allows("flax_msgpack"):
        scanner_class = _registry.load_scanner_by_id("flax_msgpack")
        if scanner_class is None:
            flax_result = _make_unavailable_recognized_format_result(path, "flax_msgpack", "flax_msgpack")
        else:
            flax_result = scanner_class(config=config).scan(path)
        _merge_composed_scan_result(result, flax_result)
    else:
        add_scanner_selection_skip_check(result, path, "flax_msgpack", scanner_selection, context=context)
    _deduplicate_exact_merged_findings(result)


def _make_incomplete_llamafile_routing_result(path: str, config: dict[str, Any] | None) -> ScanResult:
    """Fail closed when bounded nested Llamafile routing cannot read its marker probe."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Llamafile Routing",
        passed=False,
        message="Llamafile routing was inconclusive because bounded marker bytes could not be read",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, _LLAMAFILE_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _LLAMAFILE_ROUTING_INCOMPLETE_REASON)

    merge_executable_zip_container_findings(
        path,
        result,
        config,
        context="inconclusive nested executable ZIP polyglot",
    )

    result.finish(success=False)
    return result


def _make_incomplete_nemo_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded nested NeMo structural routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="NeMo Routing",
        passed=False,
        message="NeMo routing was inconclusive because the bounded TAR member probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": NEMO_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, "nemo_routing_incomplete")
    mark_operational_scan_error(result, "nemo_routing_incomplete")
    result.finish(success=False)
    return result


def _make_incomplete_mxnet_symbol_routing_result(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Fail closed when bounded nested MXNet symbol routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="MXNet Symbol Routing",
        passed=False,
        message="MXNet symbol routing was inconclusive because the bounded JSON probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, _MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON)

    from .jax_checkpoint_scanner import JaxCheckpointScanner
    from .jinja2_template_scanner import Jinja2TemplateScanner
    from .manifest_scanner import ManifestScanner
    from .mxnet_scanner import MXNetScanner

    scanner_selection = policy_from_config(config)

    def merge_owner_result(owner_result: ScanResult) -> None:
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        owner_reasons = list(owner_result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        result.metadata["scan_outcome_reasons"] = list(dict.fromkeys([*owner_reasons, *existing_reasons]))

    if os.path.splitext(path)[1].lower() == ".params":
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

    if os.path.getsize(path) <= JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES:
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
    """Fail closed when bounded nested UBJSON routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="XGBoost UBJSON Routing",
        passed=False,
        message="XGBoost UBJSON routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, "xgboost_ubjson_routing_incomplete")
    mark_operational_scan_error(result, "xgboost_ubjson_routing_incomplete")
    result.finish(success=False)
    return result


def _make_incomplete_tensorflow_protobuf_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded nested TensorFlow protobuf routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="TensorFlow Protobuf Routing",
        passed=False,
        message="TensorFlow protobuf routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, _TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _TENSORFLOW_PROTOBUF_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_onnx_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded nested ONNX protobuf routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="ONNX Routing",
        passed=False,
        message="ONNX routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": ONNX_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, _ONNX_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _ONNX_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def _make_incomplete_pickle_routing_result(path: str) -> ScanResult:
    """Fail closed when bounded nested protocol-less Pickle routing cannot decide."""
    result = ScanResult(scanner_name="unknown")
    result.add_check(
        name="Pickle Routing",
        passed=False,
        message="Pickle routing was inconclusive because the bounded structural probe reached its limit",
        severity=IssueSeverity.INFO,
        location=path,
        details={"format": PICKLE_ROUTING_INCONCLUSIVE_FORMAT, "path": path},
    )
    mark_inconclusive_scan_result(result, _PICKLE_ROUTING_INCOMPLETE_REASON)
    mark_operational_scan_error(result, _PICKLE_ROUTING_INCOMPLETE_REASON)
    result.finish(success=False)
    return result


def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Scan an extracted archive member without importing `modelaudit.core`."""
    from . import _registry
    from .zip_scanner import ZipPreflightRejected, ZipScanner

    scanner_selection = policy_from_config(config)
    hdf5_signature_offset = find_hdf5_signature_offset(path)
    safetensors_overlap_scanner_ids = detect_safetensors_overlap_scanner_ids(path)
    is_safetensors_hdf5_overlap = hdf5_signature_offset is not None and bool(safetensors_overlap_scanner_ids)
    if is_safetensors_hdf5_overlap:
        safetensors_overlap_scanner_ids |= {"safetensors"}

    def with_safetensors_overlap(result: ScanResult) -> ScanResult:
        if (
            is_safetensors_hdf5_overlap
            and hdf5_signature_offset not in (None, 0)
            and allows_zip_content_analysis(scanner_selection)
        ):
            assert hdf5_signature_offset is not None
            merge_hdf5_userblock_zip_findings(
                path,
                result,
                config,
                hdf5_signature_offset,
                context="nested HDF5 user-block ZIP",
            )
        merge_safetensors_overlap_analysis(
            path,
            result,
            config,
            scanner_selection,
            safetensors_overlap_scanner_ids,
        )
        return result

    raw_config = config or {}
    try:
        max_zip_entries = int(raw_config.get("max_zip_entries", ZipScanner.DEFAULT_MAX_ENTRIES))
    except (TypeError, ValueError):
        max_zip_entries = ZipScanner.DEFAULT_MAX_ENTRIES
    max_zip_directory_size = ZipScanner.central_directory_size_limit(raw_config)
    if (
        (not is_safetensors_hdf5_overlap or hdf5_signature_offset in (None, 0))
        and allows_zip_structure_analysis(scanner_selection, path)
        and ZipScanner.requires_preflight_result(
            path,
            max_zip_entries,
            max_zip_directory_size,
        )
    ):
        return with_safetensors_overlap(ZipScanner(config=config).scan(path))
    scanner_class = None
    routed_content_format = detect_file_format(path)
    trusted_content_format = detect_file_format_from_magic(path)
    if is_safetensors_hdf5_overlap:
        trusted_content_format = "hdf5"
    skipped_overlap_scanner_id: str | None = None
    if (
        trusted_content_format == "xgboost"
        and scanner_selection.active
        and scanner_selection.allows("mxnet")
        and not scanner_selection.allows("xgboost")
    ):
        selected_mxnet_route = detect_mxnet_symbol_content_route(path)
        if selected_mxnet_route == "mxnet":
            config = dict(config or {})
            config[MXNET_PREFERRED_XGBOOST_SKIP_PATH_CONFIG_KEY] = str(Path(path).resolve())
            trusted_content_format = "mxnet"
            skipped_overlap_scanner_id = "xgboost"
        elif selected_mxnet_route == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
            trusted_content_format = MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT
            skipped_overlap_scanner_id = "xgboost"
    if (
        trusted_content_format in {"mxnet", MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT}
        and os.path.splitext(path)[1].lower() != ".json"
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
        trusted_content_format = "xgboost"
    if (
        trusted_content_format == "xgboost"
        and os.path.splitext(path)[1].lower() != ".json"
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
        config = dict(config or {})
        configure_content_routed_json_scan(config, max_bytes=MXNET_SYMBOL_SIGNATURE_READ_BYTES)
    if trusted_content_format == "unknown":
        xgboost_route = detect_xgboost_ubjson_content_route(path)
        if xgboost_route is not None:
            trusted_content_format = xgboost_route
            if xgboost_route == "xgboost":
                config = dict(config or {})
                config[XGBOOST_CONTENT_ROUTED_UBJSON_CONFIG_KEY] = True
    if trusted_content_format == LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_llamafile_routing_result(path, config))
    if trusted_content_format == NEMO_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_nemo_routing_result(path))
    if trusted_content_format == MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT:
        result = _make_incomplete_mxnet_symbol_routing_result(path, config)
        if skipped_overlap_scanner_id:
            add_scanner_selection_skip_check(
                result,
                path,
                skipped_overlap_scanner_id,
                scanner_selection,
                context="overlapping JSON analysis",
                kind=SCANNER_SELECTION_PREFERRED_KIND,
            )
        return with_safetensors_overlap(result)
    if trusted_content_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_xgboost_ubjson_routing_result(path))
    if trusted_content_format == ONNX_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_onnx_routing_result(path))
    if trusted_content_format == PICKLE_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_pickle_routing_result(path))
    if trusted_content_format == TENSORFLOW_PROTOBUF_ROUTING_INCONCLUSIVE_FORMAT:
        return with_safetensors_overlap(_make_incomplete_tensorflow_protobuf_routing_result(path))
    if trusted_content_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT:
        result = ScanResult(scanner_name="zip")
        merge_executable_zip_container_findings(
            path,
            result,
            config,
            context="nested executable ZIP polyglot",
        )
        result.finish(success=not result.has_errors)
        return with_safetensors_overlap(result)

    header_format_override = trusted_content_format if trusted_content_format in {"hdf5", "mxnet", "xgboost"} else None
    try:
        scanner_id = _select_nested_scanner_id(path, header_format_override, config)
    except ZipPreflightRejected as exc:
        return with_safetensors_overlap(exc.result)
    pytorch_binary_supplemental_scanner_id = (
        detect_pytorch_binary_supplemental_format(path)
        if os.path.splitext(path)[1].lower() == ".bin" and scanner_id == "pytorch_binary"
        else None
    )
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
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if (
            scanner_class is None
            and trusted_content_format != "unknown"
            and scanner_id != PROTOBUF_MODEL_CANDIDATE_FORMAT
        ):
            unavailable_preferred_scanner_id = scanner_id
        if (
            scanner_class
            and scanner_id != trusted_flax_overlap_scanner_id
            and not _nested_scanner_can_handle(
                scanner_class,
                scanner_id,
                path,
                header_format_override,
            )
        ):
            scanner_class = None
    elif scanner_id:
        skipped_preferred_scanner_id = scanner_id

    if scanner_class is None:
        if (
            skipped_preferred_scanner_id == "pytorch_binary"
            and pytorch_binary_supplemental_scanner_id is not None
            and scanner_selection.allows(pytorch_binary_supplemental_scanner_id)
        ):
            scanner_class = _registry.load_scanner_by_id(pytorch_binary_supplemental_scanner_id)
        if scanner_class is None and unavailable_preferred_scanner_id is not None:
            fallback_scanner_id = _HEADER_FORMAT_TO_SCANNER_ID.get(trusted_content_format)
            if (
                fallback_scanner_id
                and fallback_scanner_id != unavailable_preferred_scanner_id
                and scanner_selection.allows(fallback_scanner_id)
            ):
                scanner_class = _registry.load_scanner_by_id(fallback_scanner_id)
        elif scanner_class is None and scanner_selection.active:
            scanner_class = _registry.get_scanner_for_path(path, scanner_selection=scanner_selection)
        elif scanner_class is None:
            scanner_class = _registry.get_scanner_for_path(path)

    if scanner_class is None:
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
                return with_safetensors_overlap(
                    make_scanner_selection_skip_result(path, candidate_scanner_id, scanner_selection)
                )

        if trusted_content_format == XML_MODEL_INCONCLUSIVE_FORMAT:
            return with_safetensors_overlap(_make_incomplete_xml_model_result(path))
        if routed_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
            return with_safetensors_overlap(_make_incomplete_protobuf_model_result(path))
        if trusted_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT and routed_content_format != "unknown":
            return with_safetensors_overlap(
                _make_unavailable_recognized_format_result(path, routed_content_format, scanner_id)
            )
        if trusted_content_format != "unknown":
            return with_safetensors_overlap(
                _make_unavailable_recognized_format_result(path, trusted_content_format, scanner_id)
            )

        result = ScanResult(scanner_name="unknown")
        result.finish(success=True)
        return with_safetensors_overlap(result)

    scanner_config = dict(config or {})
    if routed_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        existing_format_validation = scanner_config.get(FORMAT_VALIDATION_CONFIG_KEY)
        format_validation = dict(existing_format_validation) if isinstance(existing_format_validation, dict) else {}
        format_validation["header_format"] = PROTOBUF_MODEL_CANDIDATE_FORMAT
        format_validation["routed_format"] = PROTOBUF_MODEL_CANDIDATE_FORMAT
        scanner_config[FORMAT_VALIDATION_CONFIG_KEY] = format_validation

    if unavailable_preferred_scanner_id is not None:
        scanner_config["cache_enabled"] = False
    scanner = scanner_class(config=scanner_config)
    result = scanner.scan(path) if unavailable_preferred_scanner_id is not None else scanner.scan_with_cache(path)
    if unavailable_preferred_scanner_id is not None:
        result.merge(
            _make_unavailable_recognized_format_result(
                path,
                unavailable_preferred_scanner_id,
                unavailable_preferred_scanner_id,
            )
        )
        # Refresh late metadata so incomplete coverage restores whitelist-downgraded findings.
        mark_inconclusive_scan_result(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
        mark_operational_scan_error(result, _RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON)
    if result.scanner_name == "flax_msgpack":
        merge_flax_msgpack_overlap_findings(
            path,
            result,
            config,
            context="nested Flax MessagePack overlapping content analysis",
        )
    elif skipped_preferred_scanner_id == "flax_msgpack":
        merge_flax_msgpack_overlap_findings(
            path,
            result,
            config,
            context="nested Flax MessagePack overlapping content analysis",
            scanned_scanner_ids=frozenset({result.scanner_name}),
        )
    elif result.scanner_name != "flax_msgpack":
        merge_inconclusive_flax_msgpack_outcome(
            path,
            result,
            config,
            context="nested strict content owner overlapping ambiguous Flax analysis",
        )
    if skipped_overlap_scanner_id:
        add_scanner_selection_skip_check(
            result,
            path,
            skipped_overlap_scanner_id,
            scanner_selection,
            context="overlapping JSON analysis",
            kind=SCANNER_SELECTION_PREFERRED_KIND,
        )
    if skipped_preferred_scanner_id:
        add_scanner_selection_skip_check(
            result,
            path,
            skipped_preferred_scanner_id,
            scanner_selection,
            context="preferred nested scanner",
            kind=SCANNER_SELECTION_PREFERRED_KIND,
        )
    if scanner_id == "pytorch_binary" and result.scanner_name == "pytorch_binary":
        _merge_pytorch_binary_supplemental_analysis(
            path,
            result,
            config,
            pytorch_binary_supplemental_scanner_id,
        )
    return with_safetensors_overlap(result)
