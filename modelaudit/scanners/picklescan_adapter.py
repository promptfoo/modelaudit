"""Adapt standalone pickle reports into ModelAudit ScanResult objects."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from modelaudit_picklescan import Finding, PickleReport, ScanOptions, ScanStatus, Severity

from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, Check, Issue, IssueSeverity, ScanResult
from .rule_mapper import get_generic_rule_code, get_import_rule_code, get_pickle_opcode_rule_code

_INCONCLUSIVE_NOTICE_CODES = frozenset({"opcode_budget", "parse_incomplete", "timeout"})
_DEFAULT_SCAN_OPTIONS = ScanOptions()
_IMPORT_MODULE_ALIASES = {
    "nt": "os",
    "posix": "os",
}
_LEGACY_NOTICE_RULE_CODES = {
    "opcode_budget": "S902",
    "parse_incomplete": "S902",
    "timeout": "S902",
}
_LEGACY_SCAN_OUTCOME_REASONS = {
    "opcode_budget": "opcode_budget_exceeded",
    "parse_incomplete": "pickle_analysis_incomplete",
    "timeout": "scan_timeout",
}
_LEGACY_RULE_CODE_RE = re.compile(r"^S\d+$")
_LOCATION_POSITION_RE = re.compile(r"\(pos\s+(?P<position>\d+)\)\s*$")


def _parse_positive_float(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 and parsed == parsed and parsed not in {float("inf"), float("-inf")} else default


def _parse_min_int(value: Any, default: int, *, minimum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
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
                _DEFAULT_SCAN_OPTIONS.post_budget_scan_bytes,
            ),
            _DEFAULT_SCAN_OPTIONS.post_budget_scan_bytes,
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
    result = ScanResult(scanner_name=scanner_name, scanner=scanner)
    result.bytes_scanned = report.coverage.bytes_scanned
    result.metadata.update(report.metadata)
    result.metadata["pickle_report_status"] = report.status.value
    result.metadata["pickle_verdict"] = report.verdict.value
    result.metadata["pickle_source"] = report.source
    result.metadata["pickle_coverage"] = report.coverage.to_dict()

    if report.status == ScanStatus.INCONCLUSIVE:
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata["scan_outcome_reasons"] = [
            _legacy_scan_outcome_reason(notice.code)
            for notice in report.notices
            if notice.code in _INCONCLUSIVE_NOTICE_CODES
        ] or ["pickle_analysis_incomplete"]
        result.metadata["analysis_incomplete"] = True

    for finding in report.findings:
        details = _add_legacy_detail_aliases(
            {
                "pickle_source": report.source,
                **finding.details,
            }
        )
        if finding.rule_code:
            details.setdefault("pickle_rule_code", finding.rule_code)
        result.add_check(
            name="Standalone Pickle Finding",
            passed=False,
            message=finding.message,
            severity=_to_issue_severity(finding.severity),
            location=finding.location,
            details=details,
            why=finding.why,
            rule_code=_legacy_rule_code_for_finding(finding),
        )

    for notice in report.notices:
        details = {
            "pickle_source": report.source,
            "notice_code": notice.code,
            **notice.details,
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
        if notice.code == "parse_incomplete":
            result.add_check(
                name="Standalone Pickle Parse Failure",
                passed=False,
                message="Pickle parsing failed before full scan completion",
                severity=IssueSeverity.CRITICAL,
                location=notice.location,
                details={
                    "pickle_source": report.source,
                    "file_type": "pickle",
                    "parse_error": notice.details.get("exception"),
                    "exception_type": notice.details.get("exception_type"),
                    "parsing_failed": True,
                    "failure_reason": "unknown_opcode_or_format_error",
                    "analysis_incomplete": True,
                },
                why=(
                    "The scanner could not fully parse this pickle payload due to an opcode or format error. "
                    "Because full opcode analysis did not complete, the payload is treated as unsafe."
                ),
            )

    import_references = report.metadata.get("import_references", [])
    finding_ref_keys = _finding_reference_keys(report.findings)
    if isinstance(import_references, list):
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
        result.add_check(
            name="Standalone Pickle Error",
            passed=False,
            message=error.message,
            severity=IssueSeverity.CRITICAL,
            location=error.location,
            details={
                "pickle_source": report.source,
                "category": error.category,
                "exception_type": error.exception_type,
                **error.details,
            },
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

    scan_success = report.status == ScanStatus.COMPLETE or (
        report.status == ScanStatus.INCONCLUSIVE and report.has_security_findings
    )
    result.finish(success=scan_success)
    return result


def apply_pickle_member_context(result: ScanResult, *, archive_path: str, member_name: str) -> None:
    """Annotate embedded-pickle checks/issues with archive member context."""
    member_location = f"{archive_path}:{member_name}"
    for check in result.checks:
        _apply_member_context_to_record(check, member_name=member_name, member_location=member_location)
    for issue in result.issues:
        _apply_member_context_to_record(issue, member_name=member_name, member_location=member_location)


def _to_issue_severity(severity: Severity) -> IssueSeverity:
    return IssueSeverity(severity.value)


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
    if "(pos " in record.location:
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
    if finding.rule_code in {"DANGEROUS_CALL", "DANGEROUS_GLOBAL"}:
        opcode = finding.details.get("opcode")
        if isinstance(opcode, str):
            mapped = get_pickle_opcode_rule_code(opcode)
            if mapped:
                return mapped
        module = finding.details.get("module")
        name = finding.details.get("name")
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
    return finding.rule_code


def _finding_reference_keys(findings: tuple[Finding, ...]) -> set[tuple[str, int | None]]:
    keys: set[tuple[str, int | None]] = set()
    for finding in findings:
        import_reference = finding.details.get("import_reference")
        if not isinstance(import_reference, str):
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
            keys.update((import_reference, position) for position in positions)
        else:
            keys.add((import_reference, None))
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
    return details
