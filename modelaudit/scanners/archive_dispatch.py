"""Nested archive dispatch helpers used by recursive scanners."""

import json
import os
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core_results import mark_operational_scan_error
from ..scanner_registry_metadata import get_scanner_registry_metadata
from ..scanner_results import IssueSeverity, ScanResult, mark_inconclusive_scan_result
from ..scanner_selection import (
    SCANNER_SELECTION_PREFERRED_KIND,
    add_scanner_selection_skip_check,
    make_scanner_selection_skip_result,
    policy_from_config,
)
from ..utils.file.detection import (
    EXECUTABLE_ZIP_POLYGLOT_FORMAT,
    LLAMAFILE_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_ROUTING_INCONCLUSIVE_FORMAT,
    MXNET_SYMBOL_SIGNATURE_READ_BYTES,
    NEMO_ROUTING_INCONCLUSIVE_FORMAT,
    XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT,
    XML_MODEL_INCONCLUSIVE_FORMAT,
    detect_file_format,
    detect_file_format_from_magic,
    detect_mxnet_symbol_content_route,
    detect_xgboost_ubjson_content_route,
    is_executorch_archive,
    is_keras_zip_archive,
    is_pytorch_zip_archive,
    is_skops_archive,
    is_torchserve_mar_archive,
)
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
_LLAMAFILE_ROUTING_INCOMPLETE_REASON = "llamafile_routing_incomplete"
_MXNET_SYMBOL_ROUTING_INCOMPLETE_REASON = "mxnet_symbol_routing_incomplete"
SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY = "_skip_composed_archive_member_scan"


def _select_nested_scanner_id(path: str, header_format_override: str | None = None) -> str | None:
    """Select a scanner for extracted archive members using trusted file structure first."""
    header_format = header_format_override or detect_file_format(path)
    ext = os.path.splitext(path)[1].lower()

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

    return _HEADER_FORMAT_TO_SCANNER_ID.get(header_format)


def _is_direct_header_route(scanner_id: str, header_format: str) -> bool:
    """Return whether the detected header directly maps to this scanner."""
    return header_format != "unknown" and _HEADER_FORMAT_TO_SCANNER_ID.get(header_format) == scanner_id


def _nested_scanner_can_handle(
    scanner_class: type[Any],
    scanner_id: str,
    path: str,
    header_format_override: str | None = None,
) -> bool:
    """Honor trusted header routing even when temporary archive paths are suffix-gated."""
    if scanner_class.can_handle(path):
        return True

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


def merge_executable_zip_container_findings(
    path: str,
    result: ScanResult,
    config: dict[str, Any] | None,
    *,
    context: str,
) -> None:
    """Merge all enabled subtype checks and one generic ZIP member traversal."""
    from . import _registry
    from .zip_scanner import ZipScanner

    try:
        if not zipfile.is_zipfile(path):
            return
    except OSError:
        return

    scanner_selection = policy_from_config(config)
    ext = os.path.splitext(path)[1].lower()
    subtype_ids: list[str] = []
    if is_torchserve_mar_archive(path):
        subtype_ids.append("torchserve_mar")
    if is_keras_zip_archive(path, allow_config_only=ext == ".keras"):
        subtype_ids.append("keras_zip")
    if is_pytorch_zip_archive(path):
        subtype_ids.append("pytorch_zip")
    if is_executorch_archive(path):
        subtype_ids.append("executorch")
    if is_skops_archive(path):
        subtype_ids.append("skops")

    subtype_config = dict(config or {})
    subtype_config[SKIP_COMPOSED_ARCHIVE_MEMBER_SCAN_CONFIG_KEY] = True
    for subtype_id in subtype_ids:
        if scanner_selection.allows(subtype_id):
            subtype_scanner = _registry.load_scanner_by_id(subtype_id)
            if subtype_scanner:
                result.merge(subtype_scanner(config=subtype_config).scan(path))
        else:
            add_scanner_selection_skip_check(
                result,
                path,
                subtype_id,
                scanner_selection,
                context=f"{context} subtype analysis",
            )

    if scanner_selection.allows("zip"):
        result.merge(ZipScanner(config=config).scan_archive_members(path))
    else:
        add_scanner_selection_skip_check(
            result,
            path,
            "zip",
            scanner_selection,
            context=f"{context} ZIP member analysis",
        )

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

    from .jinja2_template_scanner import Jinja2TemplateScanner
    from .manifest_scanner import ManifestScanner
    from .mxnet_scanner import MXNetScanner

    scanner_selection = policy_from_config(config)

    def merge_owner_result(owner_result: ScanResult) -> None:
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        for reason in existing_reasons:
            mark_inconclusive_scan_result(result, reason)

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


def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Scan an extracted archive member without importing `modelaudit.core`."""
    from . import _registry

    scanner_selection = policy_from_config(config)
    scanner_class = None
    trusted_content_format = detect_file_format_from_magic(path)
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
        return _make_incomplete_llamafile_routing_result(path, config)
    if trusted_content_format == NEMO_ROUTING_INCONCLUSIVE_FORMAT:
        return _make_incomplete_nemo_routing_result(path)
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
        return result
    if trusted_content_format == XGBOOST_UBJSON_ROUTING_INCONCLUSIVE_FORMAT:
        return _make_incomplete_xgboost_ubjson_routing_result(path)
    if trusted_content_format == EXECUTABLE_ZIP_POLYGLOT_FORMAT:
        result = ScanResult(scanner_name="zip")
        merge_executable_zip_container_findings(
            path,
            result,
            config,
            context="nested executable ZIP polyglot",
        )
        result.finish(success=not result.has_errors)
        return result

    header_format_override = trusted_content_format if trusted_content_format in {"mxnet", "xgboost"} else None
    scanner_id = _select_nested_scanner_id(path, header_format_override)
    skipped_preferred_scanner_id: str | None = None
    if scanner_id and scanner_selection.allows(scanner_id):
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if scanner_class and not _nested_scanner_can_handle(
            scanner_class,
            scanner_id,
            path,
            header_format_override,
        ):
            scanner_class = None
    elif scanner_id:
        skipped_preferred_scanner_id = scanner_id

    if scanner_class is None:
        if scanner_selection.active:
            scanner_class = _registry.get_scanner_for_path(path, scanner_selection=scanner_selection)
        else:
            scanner_class = _registry.get_scanner_for_path(path)

    if scanner_class is None:
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
                return make_scanner_selection_skip_result(path, candidate_scanner_id, scanner_selection)

        if trusted_content_format == XML_MODEL_INCONCLUSIVE_FORMAT:
            return _make_incomplete_xml_model_result(path)
        if trusted_content_format != "unknown":
            return _make_unavailable_recognized_format_result(path, trusted_content_format, scanner_id)

        result = ScanResult(scanner_name="unknown")
        result.finish(success=True)
        return result

    scanner = scanner_class(config=config)
    result = scanner.scan_with_cache(path)
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
    return result
