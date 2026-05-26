"""Nested archive dispatch helpers used by recursive scanners."""

from collections.abc import Callable
from typing import Any

from ..core_results import mark_operational_scan_error
from ..scanner_results import IssueSeverity, ScanResult, mark_inconclusive_scan_result
from ..scanner_selection import (
    SCANNER_SELECTION_PREFERRED_KIND,
    add_scanner_selection_skip_check,
    allows_protobuf_model_candidate_analysis,
    make_scanner_selection_skip_result,
    policy_from_config,
)
from ..utils.file.detection import (
    PROTOBUF_MODEL_CANDIDATE_FORMAT,
    XML_MODEL_INCONCLUSIVE_FORMAT,
    detect_file_format,
    detect_file_format_from_magic,
)
from .base import FORMAT_VALIDATION_CONFIG_KEY
from .routing import (
    HEADER_FORMAT_TO_SCANNER_ID,
    routed_scanner_can_handle,
    select_routed_scanner_id,
)

NESTED_SCAN_CALLBACK_CONFIG_KEY = "_archive_nested_scan_callback"
NestedScanCallback = Callable[[str, dict[str, Any] | None], ScanResult]

# Compatibility export for registry and archive-dispatch tests.
_HEADER_FORMAT_TO_SCANNER_ID = HEADER_FORMAT_TO_SCANNER_ID

_RECOGNIZED_FORMAT_SCANNER_UNAVAILABLE_REASON = "recognized_format_scanner_unavailable"
_XML_MODEL_ROUTING_INCOMPLETE_REASON = "xml_model_routing_incomplete"
_PROTOBUF_MODEL_ROUTING_INCOMPLETE_REASON = "protobuf_model_routing_incomplete"


def _select_nested_scanner_id(path: str, *, header_format: str | None = None) -> str | None:
    """Select a scanner for extracted archive members using trusted file structure first."""
    if header_format is None:
        header_format = detect_file_format(path)
    return select_routed_scanner_id(path, header_format)


def _nested_scanner_can_handle(scanner_class: type[Any], scanner_id: str, path: str) -> bool:
    """Honor trusted header routing even when temporary archive paths are suffix-gated."""
    try:
        header_format = detect_file_format(path)
    except Exception:
        return False

    return routed_scanner_can_handle(scanner_class, scanner_id, header_format, path)


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


def scan_nested_file(path: str, config: dict[str, Any] | None = None) -> ScanResult:
    """Scan an extracted archive member without importing `modelaudit.core`."""
    from . import _registry

    scanner_selection = policy_from_config(config)
    scanner_class = None
    routed_content_format = detect_file_format(path)
    scanner_id = _select_nested_scanner_id(path, header_format=routed_content_format)
    trusted_content_format = detect_file_format_from_magic(path)
    skipped_preferred_scanner_id: str | None = None
    if scanner_id and (
        scanner_selection.allows(scanner_id)
        or (scanner_id == "protobuf_model_candidate" and allows_protobuf_model_candidate_analysis(scanner_selection))
    ):
        scanner_class = _registry.load_scanner_by_id(scanner_id)
        if scanner_class and not _nested_scanner_can_handle(scanner_class, scanner_id, path):
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
        if routed_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
            return _make_incomplete_protobuf_model_result(path)
        if trusted_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT and routed_content_format != "unknown":
            return _make_unavailable_recognized_format_result(path, routed_content_format, scanner_id)
        if trusted_content_format != "unknown":
            return _make_unavailable_recognized_format_result(path, trusted_content_format, scanner_id)

        result = ScanResult(scanner_name="unknown")
        result.finish(success=True)
        return result

    scanner_config = dict(config or {})
    if routed_content_format == PROTOBUF_MODEL_CANDIDATE_FORMAT:
        existing_format_validation = scanner_config.get(FORMAT_VALIDATION_CONFIG_KEY)
        format_validation = dict(existing_format_validation) if isinstance(existing_format_validation, dict) else {}
        format_validation["header_format"] = PROTOBUF_MODEL_CANDIDATE_FORMAT
        format_validation["routed_format"] = PROTOBUF_MODEL_CANDIDATE_FORMAT
        scanner_config[FORMAT_VALIDATION_CONFIG_KEY] = format_validation

    scanner = scanner_class(config=scanner_config)
    result = scanner.scan_with_cache(path)
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
