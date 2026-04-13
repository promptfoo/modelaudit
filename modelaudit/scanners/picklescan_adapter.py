"""Adapt standalone pickle reports into ModelAudit ScanResult objects."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from modelaudit_picklescan import Finding, PickleReport, ScanError, ScanOptions, ScanStatus, Severity

from modelaudit.config.explanations import get_import_explanation

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, Check, Issue, IssueSeverity, ScanResult
from .rule_mapper import get_generic_rule_code, get_import_rule_code, get_pickle_opcode_rule_code

_INCONCLUSIVE_NOTICE_CODES = frozenset(
    {
        "encoded_nested_payload_truncated",
        "literal_scan_truncated",
        "nested_payload_truncated",
        "nested_pickle_incomplete",
        "opcode_budget",
        "parse_incomplete",
        "timeout",
        "unbounded_stream_truncated",
    }
)
_DEFAULT_SCAN_OPTIONS = ScanOptions()
_IMPORT_MODULE_ALIASES = {
    "nt": "os",
    "posix": "os",
}
_LEGACY_NOTICE_RULE_CODES = dict.fromkeys(_INCONCLUSIVE_NOTICE_CODES, "S902")
_LEGACY_SCAN_OUTCOME_REASONS = {
    "encoded_nested_payload_truncated": "encoded_nested_payload_truncated",
    "literal_scan_truncated": "literal_scan_truncated",
    "nested_payload_truncated": "nested_payload_truncated",
    "nested_pickle_incomplete": "nested_pickle_incomplete",
    "opcode_budget": "opcode_budget_exceeded",
    "parse_incomplete": "pickle_analysis_incomplete",
    "timeout": "scan_timeout",
    "unbounded_stream_truncated": "unbounded_stream_truncated",
}
_NESTED_PAYLOAD_RULE_CODES = frozenset({"S213", "S601", "S602"})
_INT_TEXT_RE = re.compile(r"[+-]?\d+")
_LEGACY_RULE_CODE_RE = re.compile(r"^S\d+$")
_LOCATION_POSITION_RE = re.compile(r"\(pos\s+(?P<position>\d+)\)\s*$")
_BENIGN_SERIALIZATION_TAIL_MODULE_PREFIXES = frozenset(
    {
        "collections",
        "joblib",
        "numpy",
        "sklearn",
    }
)


def _parse_positive_float(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return parsed if parsed > 0 and math.isfinite(parsed) else default


def _parse_min_int(value: Any, default: int, *, minimum: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return default
    elif isinstance(value, str) and _INT_TEXT_RE.fullmatch(value.strip()) is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return parsed if parsed >= minimum else default


def scan_options_from_config(config: Mapping[str, Any]) -> ScanOptions:
    """Translate generic scanner config into standalone pickle scan options."""
    return ScanOptions(
        timeout_s=_parse_positive_float(
            config.get("timeout", _DEFAULT_SCAN_OPTIONS.timeout_s),
            _DEFAULT_SCAN_OPTIONS.timeout_s,
        ),
        max_opcodes=_parse_min_int(
            config.get("max_opcodes", _DEFAULT_SCAN_OPTIONS.max_opcodes),
            _DEFAULT_SCAN_OPTIONS.max_opcodes,
            minimum=1,
        ),
        post_budget_scan_bytes=_parse_min_int(
            config.get(
                "post_budget_global_scan_limit_bytes",
                config.get("post_budget_expansion_scan_limit_bytes", _DEFAULT_SCAN_OPTIONS.post_budget_scan_bytes),
            ),
            _DEFAULT_SCAN_OPTIONS.post_budget_scan_bytes,
            minimum=0,
        ),
        max_unbounded_stream_read_bytes=_parse_min_int(
            config.get(
                "max_unbounded_stream_read_bytes",
                _DEFAULT_SCAN_OPTIONS.max_unbounded_stream_read_bytes,
            ),
            _DEFAULT_SCAN_OPTIONS.max_unbounded_stream_read_bytes,
            minimum=1,
        ),
        max_string_literal_scan_chars=_parse_min_int(
            config.get(
                "max_string_literal_scan_chars",
                _DEFAULT_SCAN_OPTIONS.max_string_literal_scan_chars,
            ),
            _DEFAULT_SCAN_OPTIONS.max_string_literal_scan_chars,
            minimum=0,
        ),
        max_nested_pickle_bytes=_parse_min_int(
            config.get(
                "max_nested_pickle_bytes",
                _DEFAULT_SCAN_OPTIONS.max_nested_pickle_bytes,
            ),
            _DEFAULT_SCAN_OPTIONS.max_nested_pickle_bytes,
            minimum=0,
        ),
        max_nested_depth=_parse_min_int(
            config.get(
                "max_nested_depth",
                _DEFAULT_SCAN_OPTIONS.max_nested_depth,
            ),
            _DEFAULT_SCAN_OPTIONS.max_nested_depth,
            minimum=0,
        ),
    )


def pickle_report_to_scan_result(
    report: PickleReport,
    *,
    scanner_name: str = "pickle",
    scanner: BaseScanner | None = None,
) -> ScanResult:
    """Convert a standalone PickleReport into the repository's ScanResult model."""
    report_dict = report.to_dict()
    report_metadata = report_dict["metadata"]
    result = ScanResult(scanner_name=scanner_name, scanner=scanner)
    result.bytes_scanned = report.coverage.bytes_scanned
    result.metadata.update(report_metadata)
    result.metadata["pickle_report_status"] = report.status.value
    result.metadata["pickle_verdict"] = report.verdict.value
    result.metadata["pickle_source"] = report.source
    result.metadata["pickle_coverage"] = report.coverage.to_dict()
    suppress_parse_failure_escalation = _should_suppress_parse_failure_escalation(report)
    if suppress_parse_failure_escalation:
        result.metadata["trusted_incomplete_tail"] = True
    has_only_parse_errors = bool(report.errors) and all(error.category == "parse_error" for error in report.errors)

    if report.status == ScanStatus.INCONCLUSIVE:
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = [
            _legacy_scan_outcome_reason(notice.code)
            for notice in report.notices
            if notice.code in _INCONCLUSIVE_NOTICE_CODES
        ] or ["pickle_analysis_incomplete"]
        result.metadata["analysis_incomplete"] = True
    elif report.status == ScanStatus.ERROR and any(error.category == "parse_error" for error in report.errors):
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = ["pickle_analysis_incomplete"]
        result.metadata["analysis_incomplete"] = True
        result.metadata["file_type"] = "pickle"
        result.metadata["parsing_failed"] = True
        result.metadata["failure_reason"] = "unknown_opcode_or_format_error"

    dangerous_nested_encodings = _dangerous_nested_encodings(report.findings)

    for finding in report.findings:
        details = _add_legacy_detail_aliases(
            {
                "pickle_source": report.source,
                **finding.to_dict()["details"],
            }
        )
        if finding.rule_code:
            details.setdefault("pickle_rule_code", finding.rule_code)
        severity = _to_issue_severity(finding.severity)
        if finding.rule_code == "STRUCTURAL_TAMPER":
            severity = IssueSeverity.INFO
        if _is_benign_nested_payload_detection(finding, dangerous_nested_encodings):
            severity = IssueSeverity.INFO
            details.setdefault("evidence", "nested_payload_detected")
        legacy_rule_code = _legacy_rule_code_for_finding(finding)
        _add_legacy_rule_alias_metadata(finding, details, legacy_rule_code)
        result.add_check(
            name=_legacy_check_name_for_finding(finding),
            passed=False,
            message=finding.message,
            severity=severity,
            location=finding.location,
            details=details,
            why=_legacy_why_for_finding(finding),
            rule_code=legacy_rule_code,
        )
        _add_legacy_supporting_finding_checks(
            result,
            finding=finding,
            details=details,
            severity=severity,
            primary_rule_code=legacy_rule_code,
        )

    for notice in report.notices:
        details = {
            "pickle_source": report.source,
            "notice_code": notice.code,
            **notice.to_dict()["details"],
        }
        details.setdefault("pickle_notice_code", notice.code)
        result.add_check(
            name="Standalone Pickle Notice",
            passed=notice.code not in _INCONCLUSIVE_NOTICE_CODES,
            message=notice.message,
            severity=_to_issue_severity(notice.severity),
            location=notice.location,
            details=details,
            rule_code=_legacy_rule_code_for_notice(notice.code),
        )
        if notice.code == "parse_incomplete" and not suppress_parse_failure_escalation:
            parse_failure_details = {
                "pickle_source": report.source,
                "file_type": "pickle",
                "category": "parse_error",
                "parse_error": notice.details.get("exception"),
                "exception_type": notice.details.get("exception_type"),
                "parsing_failed": True,
                "failure_reason": "unknown_opcode_or_format_error",
                "analysis_incomplete": True,
            }
            result.metadata.update(
                {
                    "file_type": "pickle",
                    "parsing_failed": True,
                    "failure_reason": "unknown_opcode_or_format_error",
                }
            )
            result.add_check(
                name="Pickle Format Check",
                passed=False,
                message="Pickle parsing failed before full scan completion",
                severity=IssueSeverity.WARNING,
                location=notice.location,
                details=parse_failure_details,
                why=(
                    "The scanner could not fully parse this pickle payload due to an opcode or format error. "
                    "Because full opcode analysis did not complete, the payload is treated as unsafe."
                ),
                rule_code="S901",
            )

    import_references = report_metadata.get("import_references", [])
    finding_ref_keys = _finding_reference_keys(report.findings)
    if _is_reference_sequence(import_references):
        for reference in import_references:
            if not isinstance(reference, Mapping):
                continue
            if bool(reference.get("is_dangerous")):
                continue
            import_reference = reference.get("import_reference")
            position = reference.get("position")
            if isinstance(import_reference, str) and _reference_has_finding(
                import_reference, position, finding_ref_keys
            ):
                continue
            result.add_check(
                name="Standalone Pickle Import",
                passed=True,
                message=f"Observed pickle global import: {import_reference or '<unknown>'}",
                severity=IssueSeverity.INFO,
                location=(
                    f"{report.source} (pos {reference['position']})"
                    if isinstance(reference.get("position"), int)
                    else report.source
                ),
                details=_add_legacy_detail_aliases(
                    {
                        "pickle_source": report.source,
                        **dict(reference),
                    }
                ),
            )

    for error in report.errors:
        is_parse_error = error.category == "parse_error"
        result.add_check(
            name="Standalone Pickle Error",
            passed=False,
            message=error.message,
            severity=_issue_severity_for_error(error),
            location=error.location,
            details={
                "pickle_source": report.source,
                "category": error.category,
                "exception_type": error.exception_type,
                "analysis_incomplete": is_parse_error,
                **(
                    {
                        "file_type": "pickle",
                        "parsing_failed": True,
                        "failure_reason": "unknown_opcode_or_format_error",
                    }
                    if is_parse_error
                    else {}
                ),
                **error.to_dict()["details"],
            },
            rule_code="S901" if is_parse_error else None,
        )

    operational_errors = [error for error in report.errors if error.category != "parse_error"]
    if operational_errors:
        result.metadata["operational_error"] = True
        result.metadata["operational_error_reason"] = operational_errors[0].category

    if not result.checks:
        result.add_check(
            name="Standalone Pickle Scan",
            passed=True,
            message="No suspicious pickle content detected",
            location=report.source,
            details={"pickle_source": report.source},
        )

    scan_success = (
        report.status == ScanStatus.COMPLETE
        or (report.status == ScanStatus.INCONCLUSIVE and report.has_security_findings)
        or (report.status == ScanStatus.ERROR and has_only_parse_errors)
    )
    result.finish(success=scan_success)
    return result


def _issue_severity_for_error(error: ScanError) -> IssueSeverity:
    if error.category == "parse_error":
        return IssueSeverity.WARNING
    if error.category == "empty_input":
        return IssueSeverity.INFO
    return IssueSeverity.CRITICAL


def apply_pickle_member_context(result: ScanResult, *, archive_path: str, member_name: str) -> None:
    """Annotate embedded-pickle checks/issues with archive member context."""
    member_location = f"{archive_path}:{member_name}"
    for check in result.checks:
        _apply_member_context_to_record(check, member_name=member_name, member_location=member_location)
    for issue in result.issues:
        _apply_member_context_to_record(issue, member_name=member_name, member_location=member_location)


def _to_issue_severity(severity: Severity) -> IssueSeverity:
    return IssueSeverity(severity.value)


def _dangerous_nested_encodings(findings: Sequence[Finding]) -> frozenset[str]:
    encodings: set[str] = set()
    for finding in findings:
        if finding.message.startswith("Nested pickle finding:") and finding.severity in {
            Severity.WARNING,
            Severity.CRITICAL,
        }:
            encoding = finding.details.get("nested_encoding")
            if isinstance(encoding, str):
                encodings.add(encoding)
    return frozenset(encodings)


def _is_benign_nested_payload_detection(finding: Finding, dangerous_nested_encodings: frozenset[str]) -> bool:
    if finding.rule_code not in _NESTED_PAYLOAD_RULE_CODES:
        return False
    if finding.details.get("analysis_incomplete") is True:
        return False
    if finding.details.get("nested_has_execution_opcode") is not False:
        return False
    if not finding.message.startswith(("Nested pickle payload detected", "Encoded pickle payload detected")):
        return False
    encoding = finding.details.get("encoding")
    if not isinstance(encoding, str):
        if finding.rule_code == "S213":
            encoding = "raw"
        else:
            return False
    return encoding not in dangerous_nested_encodings


def _should_suppress_parse_failure_escalation(report: PickleReport) -> bool:
    """Keep known benign malformed tails as INFO notices while preserving fail-closed truncation."""
    source_ext = _pickle_source_extension(report.source)
    if report.has_security_findings:
        return False

    first_pickle_end_pos = report.metadata.get("first_pickle_end_pos")
    has_trusted_pickle_boundary = isinstance(first_pickle_end_pos, int) and first_pickle_end_pos >= 0
    if not has_trusted_pickle_boundary:
        return False

    for notice in report.notices:
        if notice.code != "parse_incomplete":
            continue

        exception_type = notice.details.get("exception_type")
        exception_message = str(notice.details.get("exception", ""))
        if (
            exception_type == "UnicodeDecodeError"
            and source_ext in {".bin", ".pkl", ".pickle"}
            and _has_no_or_only_benign_serialization_tail_imports(report)
        ):
            return True

        if exception_type not in {"ParseError", "ValueError"}:
            continue

        if (
            source_ext in {".bin", ".pkl", ".pickle", ".joblib", ".dill"}
            and _is_zero_padding_tail_parse_error(exception_message)
            and _has_no_or_only_benign_serialization_tail_imports(report)
        ):
            return True

        if (
            source_ext == ".joblib"
            and "opcode b'" in exception_message
            and exception_message.endswith(" unknown")
            and _has_only_benign_serialization_tail_imports(report)
        ):
            return True

        if (
            source_ext in {".dill", ".bin"}
            and "opcode b'" in exception_message
            and exception_message.endswith(" unknown")
            and _has_only_benign_serialization_tail_imports(report)
        ):
            return True

    return False


def _is_zero_padding_tail_parse_error(exception_message: str) -> bool:
    """Return True when parsing only failed because the trusted tail is zero padding."""
    return "opcode b'\\x00' unknown" in exception_message or 'opcode b"\\x00" unknown' in exception_message


def _pickle_source_extension(source: str) -> str:
    """Return the pickle payload extension, ignoring synthetic wrapper suffixes."""
    if source.endswith(" (decompressed)"):
        source = source[: -len(" (decompressed)")]
    return Path(source).suffix.lower()


def _has_only_benign_serialization_tail_imports(report: PickleReport) -> bool:
    import_references = report.metadata.get("import_references")
    if not _is_reference_sequence(import_references) or not import_references:
        return False

    for reference in import_references:
        if not isinstance(reference, Mapping) or bool(reference.get("is_dangerous")):
            return False
        module = reference.get("module")
        if not isinstance(module, str):
            return False
        if module not in _BENIGN_SERIALIZATION_TAIL_MODULE_PREFIXES and not any(
            module.startswith(f"{prefix}.") for prefix in _BENIGN_SERIALIZATION_TAIL_MODULE_PREFIXES
        ):
            return False

    return True


def _has_no_or_only_benign_serialization_tail_imports(report: PickleReport) -> bool:
    import_references = report.metadata.get("import_references")
    if not _is_reference_sequence(import_references) or not import_references:
        return True
    return _has_only_benign_serialization_tail_imports(report)


def _is_reference_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)


def _apply_member_context_to_record(
    record: Check | Issue,
    *,
    member_name: str,
    member_location: str,
) -> None:
    record.details["pickle_filename"] = member_name
    if not record.location:
        record.location = member_location
        return
    if record.location == member_location or record.location.startswith(f"{member_location} "):
        return
    record.location = f"{member_location} {record.location}"


def _legacy_rule_code_for_notice(notice_code: str | None) -> str | None:
    if notice_code is None:
        return None
    return _LEGACY_NOTICE_RULE_CODES.get(notice_code)


def _legacy_scan_outcome_reason(notice_code: str | None) -> str:
    if notice_code is None:
        return "pickle_analysis_incomplete"
    return _LEGACY_SCAN_OUTCOME_REASONS.get(notice_code, notice_code)


def _legacy_rule_code_for_finding(finding: Finding) -> str | None:
    if _LEGACY_RULE_CODE_RE.match(finding.rule_code or ""):
        return finding.rule_code

    if finding.rule_code == "MALFORMED_STACK_GLOBAL":
        return "S205"
    if finding.rule_code == "EXTENSION_REF":
        opcode = finding.details.get("opcode")
        if isinstance(opcode, str):
            return get_pickle_opcode_rule_code(opcode)
        return "S211"
    if finding.rule_code == "PERSISTENT_ID":
        opcode = finding.details.get("opcode")
        if isinstance(opcode, str):
            mapped = get_pickle_opcode_rule_code(opcode)
            if mapped:
                return mapped
        return "S212"
    if finding.rule_code in {"DANGEROUS_CALL", "DANGEROUS_GLOBAL"}:
        module = finding.details.get("module")
        name = finding.details.get("name")
        if isinstance(module, str) and module.lower() in {"__builtin__", "__builtins__", "builtins"}:
            if name in {"eval", "exec"}:
                return "S104"
            if name == "compile":
                return "S105"
            if name == "__import__":
                return "S106"
            return "S115"

        opcode = finding.details.get("opcode")
        if isinstance(opcode, str):
            mapped = get_pickle_opcode_rule_code(opcode)
            if mapped:
                return mapped
        if isinstance(module, str):
            mapped = get_import_rule_code(
                _IMPORT_MODULE_ALIASES.get(module.lower(), module),
                name if isinstance(name, str) else None,
            )
            if mapped:
                return mapped
        return "S201" if finding.rule_code == "DANGEROUS_CALL" else None
    if finding.rule_code == "SUSPICIOUS_STRING":
        pattern = finding.details.get("pattern")
        if isinstance(pattern, str):
            if "eval" in pattern or "exec" in pattern:
                return "S104"
            if "os.system" in pattern:
                return "S101"
            if "subprocess" in pattern:
                return "S103"
            if "__import__" in pattern:
                return "S106"
            if "compile" in pattern:
                return "S105"
            return get_generic_rule_code(pattern)
    if finding.rule_code == "POST_BUDGET_GLOBAL":
        pattern = finding.details.get("pattern")
        if isinstance(pattern, str):
            module, _, name = pattern.partition("\n")
            mapped = get_import_rule_code(
                _IMPORT_MODULE_ALIASES.get(module.lower(), module),
                name or None,
            )
            if mapped:
                return mapped
        return "S206"
    if finding.rule_code == "PICKLE_EXPANSION":
        return "S902"
    if finding.rule_code == "STRUCTURAL_TAMPER":
        return "S902"
    return finding.rule_code


def _add_legacy_rule_alias_metadata(
    finding: Finding,
    details: dict[str, Any],
    primary_rule_code: str | None,
) -> None:
    if primary_rule_code == "S115" or finding.rule_code != "DANGEROUS_CALL":
        return
    module = finding.details.get("module")
    name = finding.details.get("name")
    if (
        isinstance(module, str)
        and module.lower() in {"__builtin__", "__builtins__", "builtins"}
        and name in {"eval", "exec", "compile", "__import__"}
    ):
        details["legacy_rule_aliases"] = ["S115"]


def _legacy_check_name_for_finding(finding: Finding) -> str:
    if finding.rule_code == "PICKLE_EXPANSION":
        if finding.details.get("post_budget") is True:
            return "Post-Budget Pickle Expansion Heuristic Check"
        return "Pickle Expansion Heuristic Check"
    if finding.rule_code == "STRUCTURAL_TAMPER":
        return "Pickle Structural Tamper Check"
    opcode = finding.details.get("opcode")
    if finding.rule_code in {"DANGEROUS_CALL", "DANGEROUS_GLOBAL"} and isinstance(opcode, str):
        return f"{opcode.upper()} Opcode Safety Check"
    return "Standalone Pickle Finding"


def _add_legacy_supporting_finding_checks(
    result: ScanResult,
    *,
    finding: Finding,
    details: dict[str, Any],
    severity: IssueSeverity,
    primary_rule_code: str | None,
) -> None:
    if severity not in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}:
        return

    if (
        finding.rule_code == "MALFORMED_STACK_GLOBAL"
        and primary_rule_code != "S902"
        and finding.message.startswith("Malformed STACK_GLOBAL operands")
    ):
        result.add_check(
            name="STACK_GLOBAL Context Check",
            passed=False,
            message="STACK_GLOBAL opcode found without sufficient string context",
            severity=IssueSeverity.WARNING,
            location=finding.location,
            details=details,
            why=(
                "STACK_GLOBAL requires module and function string operands on the stack. "
                "Malformed operands can hide callable resolution from shallow scanners."
            ),
            rule_code="S902",
        )
        return

    if finding.rule_code == "DANGEROUS_CALL" and primary_rule_code != "S201" and finding.message.startswith("Found "):
        module = finding.details.get("module")
        name = finding.details.get("name")
        if (
            isinstance(module, str)
            and module.lower() in {"__builtin__", "__builtins__", "builtins"}
            and name
            in {
                "eval",
                "exec",
                "compile",
                "__import__",
            }
        ):
            result.add_check(
                name="REDUCE Opcode Safety Check",
                passed=False,
                message=finding.message,
                severity=severity,
                location=finding.location,
                details=details,
                why=_legacy_why_for_finding(finding),
                rule_code="S201",
            )
            if primary_rule_code != "S115":
                details.setdefault("legacy_rule_aliases", ["S115"])
        return

    if finding.rule_code == "DANGEROUS_GLOBAL":
        module = finding.details.get("module")
        name = finding.details.get("name")
        if not isinstance(module, str):
            return
        import_rule_code = get_import_rule_code(
            _IMPORT_MODULE_ALIASES.get(module.lower(), module),
            name if isinstance(name, str) else None,
        )
        if import_rule_code is None or import_rule_code == primary_rule_code:
            return
        result.add_check(
            name="GLOBAL Opcode Safety Check",
            passed=False,
            message=finding.message,
            severity=severity,
            location=finding.location,
            details=details,
            why=_legacy_why_for_finding(finding),
            rule_code=import_rule_code,
        )


def _finding_reference_keys(findings: tuple[Finding, ...]) -> set[tuple[str, int | None]]:
    keys: set[tuple[str, int | None]] = set()
    for finding in findings:
        import_references: set[str] = set()
        import_reference = finding.details.get("import_reference")
        if isinstance(import_reference, str):
            import_references.add(import_reference)
        else:
            module = finding.details.get("module")
            name = finding.details.get("name")
            if isinstance(module, str) and isinstance(name, str):
                import_references.add(f"{module}.{name}")
                aliased_module = _IMPORT_MODULE_ALIASES.get(module.lower())
                if aliased_module is not None:
                    import_references.add(f"{aliased_module}.{name}")

        if not import_references:
            continue

        positions = {
            value
            for value in (
                finding.details.get("global_position"),
                finding.details.get("position"),
                _location_position(finding.location),
            )
            if isinstance(value, int)
        }
        if positions:
            keys.update((reference, position) for reference in import_references for position in positions)
        else:
            keys.update((reference, None) for reference in import_references)
    return keys


def _reference_has_finding(
    import_reference: str,
    position: Any,
    finding_ref_keys: set[tuple[str, int | None]],
) -> bool:
    position_key = position if isinstance(position, int) else None
    return (import_reference, position_key) in finding_ref_keys or (import_reference, None) in finding_ref_keys


def _location_position(location: str | None) -> int | None:
    if not location:
        return None
    match = _LOCATION_POSITION_RE.search(location)
    if match is None:
        return None
    return int(match.group("position"))


def _add_legacy_detail_aliases(details: dict[str, Any]) -> dict[str, Any]:
    if "function" not in details and isinstance(details.get("name"), str):
        details["function"] = details["name"]
    if "associated_global" not in details and isinstance(details.get("import_reference"), str):
        details["associated_global"] = details["import_reference"]
    return details


def _legacy_why_for_finding(finding: Finding) -> str | None:
    if finding.rule_code not in {"DANGEROUS_CALL", "DANGEROUS_GLOBAL"}:
        return finding.why

    import_reference = finding.details.get("import_reference")
    if isinstance(import_reference, str):
        why = get_import_explanation(import_reference)
        if why is not None:
            return why

    module = finding.details.get("module")
    name = finding.details.get("name")
    if isinstance(module, str):
        if isinstance(name, str):
            why = get_import_explanation(f"{module}.{name}")
            if why is not None:
                return why
        why = get_import_explanation(module)
        if why is not None:
            return why
    return finding.why
