from __future__ import annotations

from pathlib import Path

from modelaudit_picklescan import (
    CoverageSummary,
    Finding,
    Notice,
    PickleReport,
    SafetyVerdict,
    ScanError,
    ScanOptions,
    ScanStatus,
    Severity,
)

from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, IssueSeverity
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner
from modelaudit.scanners.picklescan_adapter import (
    apply_pickle_member_context,
    pickle_report_to_scan_result,
    scan_options_from_config,
)
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from tests.helpers import create_mock_pytorch_zip


def test_scan_options_from_config_parses_string_values_and_falls_back_for_bad_values() -> None:
    defaults = ScanOptions()

    parsed = scan_options_from_config(
        {
            "timeout": "2.5",
            "max_opcodes": "4096",
            "post_budget_global_scan_limit_bytes": "not-an-int",
        }
    )

    assert parsed.timeout_s == 2.5
    assert parsed.max_opcodes == 4096
    assert parsed.post_budget_scan_bytes == defaults.post_budget_scan_bytes

    fallback = scan_options_from_config(
        {
            "timeout": float("inf"),
            "max_opcodes": 0,
            "post_budget_global_scan_limit_bytes": -1,
        }
    )

    assert fallback.timeout_s == defaults.timeout_s
    assert fallback.max_opcodes == defaults.max_opcodes
    assert fallback.post_budget_scan_bytes == defaults.post_budget_scan_bytes

    nan_fallback = scan_options_from_config({"timeout": "nan"})
    assert nan_fallback.timeout_s == defaults.timeout_s


def test_pickle_report_to_scan_result_maps_clean_report_to_successful_result() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        coverage=CoverageSummary(bytes_scanned=12, bytes_total=12, opcode_count=3),
        metadata={"protocols": [4], "opcode_count": 3},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert result.bytes_scanned == 12
    assert result.metadata["pickle_report_status"] == "complete"
    assert result.metadata["pickle_verdict"] == "clean"
    assert result.metadata["pickle_coverage"]["opcode_count"] == 3
    assert result.issues == []
    assert any(check.name == "Standalone Pickle Scan" and check.status.value == "passed" for check in result.checks)


def test_pickle_report_to_scan_result_preserves_security_findings() -> None:
    report = PickleReport(
        source="payload.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.MALICIOUS,
        findings=(
            Finding(
                message="Found dangerous global reference: posix.system",
                severity=Severity.CRITICAL,
                location="payload.pkl (pos 12)",
                rule_code="DANGEROUS_GLOBAL",
                details={"module": "posix", "name": "system"},
                why="Dangerous globals can execute code.",
            ),
        ),
        coverage=CoverageSummary(bytes_scanned=42, bytes_total=42, opcode_count=9),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert result.issues[0].rule_code == "S101"
    assert result.issues[0].details["function"] == "system"
    assert result.issues[0].details["pickle_rule_code"] == "DANGEROUS_GLOBAL"
    assert result.issues[0].details["pickle_source"] == "payload.pkl"


def test_pickle_report_to_scan_result_maps_post_budget_rule_codes_to_legacy_namespace() -> None:
    report = PickleReport(
        source="budget.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Dangerous global-like byte pattern found beyond opcode budget",
                severity=Severity.WARNING,
                location="budget.pkl (pos 128)",
                rule_code="POST_BUDGET_GLOBAL",
                details={"pattern": "posix\nsystem"},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is True
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S101"
    assert result.issues[0].details["pickle_rule_code"] == "POST_BUDGET_GLOBAL"


def test_pickle_report_to_scan_result_emits_passed_import_checks() -> None:
    report = PickleReport(
        source="safe.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.CLEAN,
        metadata={
            "import_references": [
                {
                    "import_reference": "collections.OrderedDict",
                    "module": "collections",
                    "name": "OrderedDict",
                    "opcode": "GLOBAL",
                    "position": 12,
                    "is_dangerous": False,
                }
            ]
        },
    )

    result = pickle_report_to_scan_result(report)

    import_checks = [check for check in result.checks if check.name == "Standalone Pickle Import"]
    assert len(import_checks) == 1
    assert import_checks[0].status.value == "passed"
    assert import_checks[0].location == "safe.pkl (pos 12)"
    assert import_checks[0].details["function"] == "OrderedDict"
    assert import_checks[0].details["import_reference"] == "collections.OrderedDict"


def test_pickle_report_to_scan_result_suppresses_passed_import_checks_for_references_with_findings() -> None:
    report = PickleReport(
        source="warning.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found non-allowlisted __main__ global reference: __main__.CustomModel",
                severity=Severity.WARNING,
                location="warning.pkl (pos 7)",
                rule_code="S203",
                details={
                    "opcode": "GLOBAL",
                    "module": "__main__",
                    "name": "CustomModel",
                    "import_reference": "__main__.CustomModel",
                },
            ),
        ),
        metadata={
            "import_references": [
                {
                    "import_reference": "__main__.CustomModel",
                    "module": "__main__",
                    "name": "CustomModel",
                    "opcode": "GLOBAL",
                    "position": 7,
                    "is_dangerous": False,
                }
            ]
        },
    )

    result = pickle_report_to_scan_result(report)

    assert [check.name for check in result.checks].count("Standalone Pickle Import") == 0
    assert len(result.issues) == 1
    assert result.issues[0].rule_code == "S203"


def test_pickle_report_to_scan_result_fails_closed_for_inconclusive_report_without_findings() -> None:
    report = PickleReport(
        source="budget.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Opcode budget reached",
                severity=Severity.INFO,
                location="budget.pkl",
                code="opcode_budget",
                details={"analysis_incomplete": True},
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["opcode_budget_exceeded"]
    assert result.metadata["analysis_incomplete"] is True
    assert any(
        check.name == "Standalone Pickle Notice"
        and check.status.value == "failed"
        and check.severity == IssueSeverity.INFO
        and check.rule_code == "S902"
        and check.details["pickle_notice_code"] == "opcode_budget"
        for check in result.checks
    )


def test_pickle_report_to_scan_result_escalates_parse_incomplete_notices_to_parse_failures() -> None:
    report = PickleReport(
        source="truncated.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="truncated.pkl (pos 4)",
                code="parse_incomplete",
                details={
                    "exception": "pickle exhausted before seeing STOP",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["scan_outcome_reasons"] == ["pickle_analysis_incomplete"]
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Pickle parsing failed before full scan completion"
        and issue.location == "truncated.pkl (pos 4)"
        and issue.details["parse_error"] == "pickle exhausted before seeing STOP"
        and issue.details["failure_reason"] == "unknown_opcode_or_format_error"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_escalates_parse_failure_for_truncated_bin_sources() -> None:
    report = PickleReport(
        source="truncated.bin",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: EOFError",
                severity=Severity.INFO,
                location="truncated.bin (pos 57)",
                code="parse_incomplete",
                details={
                    "exception": "pickle exhausted before seeing STOP",
                    "exception_type": "EOFError",
                    "analysis_incomplete": True,
                },
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.message == "Pickle parsing failed before full scan completion"
        and issue.location == "truncated.bin (pos 57)"
        and issue.details["parse_error"] == "pickle exhausted before seeing STOP"
        and issue.details["failure_reason"] == "unknown_opcode_or_format_error"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_trusted_bin_padding_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="weights.bin",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="weights.bin (pos 57)",
                code="parse_incomplete",
                details={
                    "exception": "at position 4096, opcode b'\\x00' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 56},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_unicode_decode_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="benign-tail.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: UnicodeDecodeError",
                severity=Severity.INFO,
                location="benign-tail.pkl (pos 21)",
                code="parse_incomplete",
                details={
                    "exception": "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
                    "exception_type": "UnicodeDecodeError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 20},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: UnicodeDecodeError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_zero_padding_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="padding.pkl",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="padding.pkl (pos 20)",
                code="parse_incomplete",
                details={
                    "exception": "at position 4096, opcode b'\\x00' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={"first_pickle_end_pos": 19},
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_joblib_unknown_opcode_tails_as_inconclusive_notices() -> None:
    report = PickleReport(
        source="numpy_arrays.joblib",
        status=ScanStatus.INCONCLUSIVE,
        verdict=SafetyVerdict.UNKNOWN,
        notices=(
            Notice(
                message="Pickle parsing stopped before the stream was fully consumed: ValueError",
                severity=Severity.INFO,
                location="numpy_arrays.joblib (pos 231)",
                code="parse_incomplete",
                details={
                    "exception": "at position 230, opcode b'\\t' unknown",
                    "exception_type": "ValueError",
                    "analysis_incomplete": True,
                },
            ),
        ),
        metadata={
            "first_pickle_end_pos": 230,
            "import_references": [
                {
                    "import_reference": "joblib.numpy_pickle.NumpyArrayWrapper",
                    "module": "joblib.numpy_pickle",
                    "name": "NumpyArrayWrapper",
                    "opcode": "STACK_GLOBAL",
                    "position": 66,
                    "is_dangerous": False,
                },
                {
                    "import_reference": "numpy.ndarray",
                    "module": "numpy",
                    "name": "ndarray",
                    "opcode": "STACK_GLOBAL",
                    "position": 103,
                    "is_dangerous": False,
                },
            ],
        },
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert not any(issue.message == "Pickle parsing failed before full scan completion" for issue in result.issues)
    assert any(
        issue.severity == IssueSeverity.INFO
        and issue.rule_code == "S902"
        and issue.message == "Pickle parsing stopped before the stream was fully consumed: ValueError"
        for issue in result.issues
    )


def test_pickle_report_to_scan_result_keeps_parse_errors_non_operational() -> None:
    report = PickleReport(
        source="bad.bin",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="Could not parse pickle stream",
                category="parse_error",
                location="bad.bin (pos 0)",
                exception_type="ValueError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert "operational_error" not in result.metadata
    assert "operational_error_reason" not in result.metadata
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL


def test_pickle_report_to_scan_result_maps_non_parse_errors_to_operational_errors() -> None:
    report = PickleReport(
        source="broken.pkl",
        status=ScanStatus.ERROR,
        verdict=SafetyVerdict.UNKNOWN,
        errors=(
            ScanError(
                message="Could not read pickle stream",
                category="io_error",
                location="broken.pkl",
                exception_type="OSError",
            ),
        ),
    )

    result = pickle_report_to_scan_result(report)

    assert result.success is False
    assert result.metadata["operational_error"] is True
    assert result.metadata["operational_error_reason"] == "io_error"
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL


def test_pytorch_zip_scanner_does_not_duplicate_member_path_in_pickle_locations(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    result = PyTorchZipScanner().scan(str(model_path))

    duplicated_location = f"{model_path}:data.pkl {model_path}:data.pkl"
    assert result.issues
    assert all(duplicated_location not in (issue.location or "") for issue in result.issues)
    assert all(duplicated_location not in (check.location or "") for check in result.checks)
    assert all(
        issue.details.get("pickle_filename") == "data.pkl"
        for issue in result.issues
        if issue.details.get("pickle_source") == f"{model_path}:data.pkl"
    )


def test_executorch_scanner_does_not_duplicate_member_path_in_pickle_locations(tmp_path: Path) -> None:
    model_path = create_mock_pytorch_zip(tmp_path / "model.pte", malicious=True)

    result = ExecuTorchScanner().scan(str(model_path))

    duplicated_location = f"{model_path}:data.pkl {model_path}:data.pkl"
    assert result.issues
    assert all(duplicated_location not in (issue.location or "") for issue in result.issues)
    assert all(duplicated_location not in (check.location or "") for check in result.checks)
    assert all(
        issue.details.get("pickle_filename") == "data.pkl"
        for issue in result.issues
        if issue.details.get("pickle_source") == f"{model_path}:data.pkl"
    )


def test_apply_pickle_member_context_prepends_member_location_without_position_markers() -> None:
    report = PickleReport(
        source="data.pkl",
        status=ScanStatus.COMPLETE,
        verdict=SafetyVerdict.SUSPICIOUS,
        findings=(
            Finding(
                message="Found non-allowlisted __main__ global reference: __main__.CustomType",
                severity=Severity.WARNING,
                location="custom-location",
                rule_code="S203",
            ),
        ),
    )
    result = pickle_report_to_scan_result(report)

    apply_pickle_member_context(result, archive_path="archive.pt", member_name="data.pkl")

    assert result.issues[0].location == "archive.pt:data.pkl custom-location"
    assert result.issues[0].details["pickle_filename"] == "data.pkl"
