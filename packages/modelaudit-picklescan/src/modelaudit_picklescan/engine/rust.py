"""Python boundary for the Rust pickle scanner extension."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from typing import Any

from ..options import ScanOptions
from ..report import CoverageSummary, Finding, Notice, PickleReport, SafetyVerdict, ScanError, ScanStatus, Severity
from .selection import RUST_EXTENSION_MODULE


def scan_pickle_payload(
    payload: bytes,
    *,
    source: str,
    options: ScanOptions,
    bytes_total: int | None = None,
    position_offset: int = 0,
    nested_depth: int = 0,
) -> PickleReport:
    """Scan bytes with the native engine and convert its raw report."""

    native_module = import_module(RUST_EXTENSION_MODULE)
    raw_report = native_module.scan_bytes(
        payload,
        source,
        _options_to_native_dict(options),
        bytes_total,
        position_offset,
        nested_depth,
    )
    if not isinstance(raw_report, Mapping):
        raise TypeError(f"Rust scanner returned {type(raw_report).__name__}, expected mapping")
    return _report_from_native_dict(raw_report)


def _options_to_native_dict(options: ScanOptions) -> dict[str, int | float]:
    return {
        "timeout_s": options.timeout_s,
        "max_opcodes": options.max_opcodes,
        "post_budget_scan_bytes": options.post_budget_scan_bytes,
        "max_string_literal_scan_chars": options.max_string_literal_scan_chars,
        "max_nested_pickle_bytes": options.max_nested_pickle_bytes,
        "max_nested_depth": options.max_nested_depth,
    }


def _report_from_native_dict(raw_report: Mapping[str, Any]) -> PickleReport:
    coverage = _mapping(raw_report.get("coverage", {}))
    return PickleReport(
        source=str(raw_report["source"]),
        status=ScanStatus(str(raw_report["status"])),
        verdict=SafetyVerdict(str(raw_report["verdict"])),
        findings=tuple(_finding_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("findings"))),
        notices=tuple(_notice_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("notices"))),
        errors=tuple(_error_from_native_dict(_mapping(item)) for item in _sequence(raw_report.get("errors"))),
        coverage=CoverageSummary(
            bytes_scanned=int(coverage.get("bytes_scanned", 0)),
            bytes_total=_optional_int(coverage.get("bytes_total")),
            opcode_count=_optional_int(coverage.get("opcode_count")),
            raw_scan_complete=_optional_bool(coverage.get("raw_scan_complete")),
            opcode_scan_complete=_optional_bool(coverage.get("opcode_scan_complete")),
        ),
        metadata=dict(_mapping(raw_report.get("metadata", {}))),
        duration_s=float(raw_report.get("duration_s", 0.0)),
    )


def _finding_from_native_dict(raw_finding: Mapping[str, Any]) -> Finding:
    return Finding(
        message=str(raw_finding["message"]),
        severity=Severity(str(raw_finding["severity"])),
        location=_optional_str(raw_finding.get("location")),
        rule_code=_optional_str(raw_finding.get("rule_code")),
        details=dict(_mapping(raw_finding.get("details", {}))),
        why=_optional_str(raw_finding.get("why")),
    )


def _notice_from_native_dict(raw_notice: Mapping[str, Any]) -> Notice:
    return Notice(
        message=str(raw_notice["message"]),
        severity=Severity(str(raw_notice.get("severity", Severity.INFO.value))),
        location=_optional_str(raw_notice.get("location")),
        code=_optional_str(raw_notice.get("code")),
        details=dict(_mapping(raw_notice.get("details", {}))),
    )


def _error_from_native_dict(raw_error: Mapping[str, Any]) -> ScanError:
    return ScanError(
        message=str(raw_error["message"]),
        category=str(raw_error["category"]),
        location=_optional_str(raw_error.get("location")),
        exception_type=_optional_str(raw_error.get("exception_type")),
        details=dict(_mapping(raw_error.get("details", {}))),
    )


def _mapping(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise TypeError(f"expected mapping, got {type(value).__name__}")


def _sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    raise TypeError(f"expected sequence, got {type(value).__name__}")


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str | bytes | bytearray):
        return int(value)
    raise TypeError(f"expected int-compatible value, got {type(value).__name__}")


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise TypeError(f"expected bool or None, got {type(value).__name__}")
