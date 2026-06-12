"""Tests specifically for exit code logic."""

import pickle
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.core_results import add_issue_to_model, results_have_inconclusive_outcome

# Ensure models are rebuilt for forward references
from modelaudit.models import ModelAuditResultModel, rebuild_models
from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity, ScanResult

rebuild_models()


def _create_result_model(**kwargs: Any) -> ModelAuditResultModel:
    """Helper function to create ModelAuditResultModel with sensible defaults."""
    from typing import Any

    defaults: dict[str, Any] = {
        "bytes_scanned": 100,
        "issues": [],
        "checks": [],
        "files_scanned": 1,
        "assets": [],
        "has_errors": False,
        "scanner_names": [],
        "file_metadata": {},
        "start_time": 0.0,
        "duration": 1.0,
        "total_checks": 0,
        "passed_checks": 0,
        "failed_checks": 0,
        "success": True,
    }
    defaults.update(kwargs)
    return ModelAuditResultModel(**defaults)


def test_exit_code_clean_scan():
    """Test exit code 0 for clean scan with no issues."""
    results = _create_result_model()
    assert determine_exit_code(results) == 0


def test_exit_code_clean_scan_with_debug_issues():
    """Test exit code 0 for scan with only debug issues."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Debug info",
                severity=IssueSeverity.DEBUG,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ]
    )
    assert determine_exit_code(results) == 0


def test_exit_code_clean_scan_with_runtime_version_skip_check() -> None:
    """Expected CVE applicability skips should not become incomplete coverage exits."""
    results = _create_result_model(
        checks=[
            Check(
                name="CVE PyTorch Version Check",
                status=CheckStatus.SKIPPED,
                message="PyTorch runtime version unavailable",
                severity=IssueSeverity.INFO,
                location="weights.pt",
                details={
                    "analysis_incomplete": True,
                    "runtime_version_known": False,
                    "runtime_cve_applicability": "unknown",
                    "runtime_cve_version_gate": "local_environment_only",
                },
                timestamp=0.0,
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is False
    assert determine_exit_code(results) == 0


def test_exit_code_security_issues():
    """Test exit code 1 for security issues found."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Suspicious operation",
                severity=IssueSeverity.WARNING,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ]
    )
    assert determine_exit_code(results) == 1


def test_exit_code_security_errors():
    """Test exit code 1 for security errors found."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Malicious code detected",
                severity=IssueSeverity.CRITICAL,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ]
    )
    assert determine_exit_code(results) == 1


def test_exit_code_operational_errors():
    """Test exit code 2 for operational errors."""
    results = _create_result_model(
        success=False,
        has_errors=True,
        issues=[
            Issue(
                message="Error during scan: File not found",
                severity=IssueSeverity.CRITICAL,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 2


def test_exit_code_mixed_issues():
    """Test that operational errors take precedence over security issues."""
    results = _create_result_model(
        success=False,
        has_errors=True,
        issues=[
            Issue(
                message="Error during scan: Scanner crashed",
                severity=IssueSeverity.CRITICAL,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
            Issue(
                message="Also found suspicious code",
                severity=IssueSeverity.WARNING,
                location="test2.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    # Operational errors (exit code 2) should take precedence
    # over security issues (exit code 1)
    assert determine_exit_code(results) == 2


def test_exit_code_mixed_severity():
    """Test with mixed severity levels (no operational errors)."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Debug info",
                severity=IssueSeverity.DEBUG,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
            Issue(
                message="Info message",
                severity=IssueSeverity.INFO,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
            Issue(
                message="Warning about something",
                severity=IssueSeverity.WARNING,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ]
    )
    # Should return 1 because there are non-debug issues
    assert determine_exit_code(results) == 1


def test_exit_code_info_level_issues():
    """Test exit code 0 for info level issues (INFO is not a security problem)."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Information about model",
                severity=IssueSeverity.INFO,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ]
    )
    assert determine_exit_code(results) == 0  # INFO level should not trigger exit code 1


def test_add_issue_to_model_unknown_severity_defaults_to_info():
    """Unknown aggregate issue severity should not become a warning."""
    results = _create_result_model()

    add_issue_to_model(results, "unknown severity diagnostic", severity="unknown")

    assert results.issues[0].severity == IssueSeverity.INFO
    assert determine_exit_code(results) == 0


def test_add_issue_to_model_missing_severity_defaults_to_info():
    """Omitted aggregate issue severity should not become a warning."""
    results = _create_result_model()

    add_issue_to_model(results, "missing severity diagnostic")

    assert results.issues[0].severity == IssueSeverity.INFO
    assert determine_exit_code(results) == 0


def test_exit_code_inconclusive_pickle_without_security_findings() -> None:
    """Explicit inconclusive outcomes should return exit code 2 when no real findings exist."""
    results = _create_result_model(
        success=False,
        file_metadata={"model.pkl": {"scan_outcome": "inconclusive"}},
    )
    assert determine_exit_code(results) == 2


def test_exit_code_inconclusive_pickle_with_info_parse_failure_without_security_findings() -> None:
    """Operational parse failures should return exit code 2, not security exit code 1."""
    results = _create_result_model(
        success=False,
        file_metadata={"model.pkl": {"scan_outcome": "inconclusive", "analysis_incomplete": True}},
        issues=[
            Issue(
                message="Pickle parsing failed before full scan completion",
                severity=IssueSeverity.INFO,
                location="model.pkl",
                details={
                    "category": "parse_error",
                    "failure_reason": "unknown_opcode_or_format_error",
                    "analysis_incomplete": True,
                },
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 2


def test_exit_code_inconclusive_pickle_with_security_findings() -> None:
    """Security findings should still return exit code 1 even if analysis was inconclusive."""
    results = _create_result_model(
        success=False,
        file_metadata={"model.pkl": {"scan_outcome": "inconclusive"}},
        issues=[
            Issue(
                message="Suspicious import found beyond opcode budget",
                severity=IssueSeverity.WARNING,
                location="model.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 1


def test_exit_code_analysis_incomplete_metadata_without_scan_outcome() -> None:
    """Incomplete coverage metadata should fail closed even before scan_outcome normalization."""
    results = _create_result_model(
        file_metadata={"model.bin": {"analysis_incomplete": True}},
    )

    assert determine_exit_code(results) == 2


def test_exit_code_incomplete_coverage_reason_without_scan_outcome() -> None:
    """Incomplete coverage reasons should be enough to drive aggregate exit semantics."""
    results = _create_result_model(
        file_metadata={"model.bin": {"scan_outcome_reasons": ["bounded_probe_exhausted"]}},
    )

    assert determine_exit_code(results) == 2


def test_exit_code_issue_details_incomplete_without_security_findings() -> None:
    """Issue-only incomplete coverage evidence should fail closed."""
    results = _create_result_model(
        issues=[
            Issue(
                message="DVC output limit exceeded - not all declared outputs were scanned",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={
                    "analysis_incomplete": True,
                    "scan_outcome": "inconclusive",
                    "reason": "dvc_output_limit_exceeded",
                },
                timestamp=0.0,
                why=None,
                type="dvc_output_limit_exceeded",
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is True
    assert determine_exit_code(results) == 2


def test_exit_code_check_details_incomplete_without_security_findings() -> None:
    """Check-only incomplete coverage evidence should also fail closed."""
    results = _create_result_model(
        checks=[
            Check(
                name="DVC Output Resolution",
                status=CheckStatus.FAILED,
                message="DVC output resolution incomplete",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
                timestamp=0.0,
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is True
    assert determine_exit_code(results) == 2


def test_exit_code_check_details_bare_analysis_incomplete_fails_closed() -> None:
    """Bare analysis_incomplete in record details is incomplete coverage evidence."""
    results = _create_result_model(
        checks=[
            Check(
                name="Embedded Secret Scan",
                status=CheckStatus.FAILED,
                message="Embedded secret scan truncated",
                severity=IssueSeverity.INFO,
                location="model.bin",
                details={"analysis_incomplete": True},
                timestamp=0.0,
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is True
    assert determine_exit_code(results) == 2


def test_exit_code_bare_analysis_incomplete_preserves_security_exit() -> None:
    """Security findings still exit 1 when bare incomplete coverage evidence coexists."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Embedded secret scan truncated",
                severity=IssueSeverity.INFO,
                location="model.bin",
                details={"analysis_incomplete": True},
                timestamp=0.0,
                why=None,
                type=None,
            ),
            Issue(
                message="Dangerous pickle global",
                severity=IssueSeverity.CRITICAL,
                location="payload.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is True
    assert determine_exit_code(results) == 1


def test_exit_code_consolidated_check_findings_preserve_incomplete_coverage() -> None:
    """Consolidated check findings should not hide detail-only incomplete coverage."""
    child = _create_result_model(
        checks=[
            Check(
                name="DVC Output Resolution",
                status=CheckStatus.FAILED,
                message="DVC output resolution incomplete",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={
                    "component_count": 2,
                    "findings": [
                        {"analysis_incomplete": True, "scan_outcome_reason": "dvc_output_limit_exceeded"},
                        {"component": "covered-sibling"},
                    ],
                },
                timestamp=0.0,
            ),
        ],
    )
    aggregate = _create_result_model()

    aggregate.aggregate_scan_result(child.model_dump())

    assert aggregate.success is False
    assert results_have_inconclusive_outcome(aggregate) is True
    assert determine_exit_code(aggregate) == 2


def test_direct_aggregate_scan_result_preserves_consolidated_incomplete_coverage() -> None:
    """Direct ScanResult aggregation should recurse through consolidated check details."""
    scan_result = ScanResult(scanner_name="synthetic")
    scan_result.add_check(
        name="DVC Output Resolution",
        passed=False,
        message="DVC output resolution incomplete",
        severity=IssueSeverity.INFO,
        location="model.dvc",
        details={
            "component_count": 2,
            "findings": [{"scan_outcome_reasons": ["dvc_output_limit_exceeded"]}],
        },
    )
    scan_result.finish(success=True)
    aggregate = _create_result_model()

    aggregate.aggregate_scan_result_direct(scan_result)

    assert aggregate.success is False
    assert results_have_inconclusive_outcome(aggregate) is True
    assert determine_exit_code(aggregate) == 2


def test_exit_code_issue_details_incomplete_with_security_findings() -> None:
    """Security findings still exit 1 while issue-only coverage remains visible."""
    results = _create_result_model(
        issues=[
            Issue(
                message="DVC output resolution incomplete",
                severity=IssueSeverity.INFO,
                location="model.dvc",
                details={"analysis_incomplete": True, "scan_outcome_reason": "dvc_analysis_incomplete"},
                timestamp=0.0,
                why=None,
                type=None,
            ),
            Issue(
                message="Dangerous pickle global",
                severity=IssueSeverity.WARNING,
                location="payload.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )

    assert results_have_inconclusive_outcome(results) is True
    assert determine_exit_code(results) == 1


def test_exit_code_empty_coverage_reason_placeholder_remains_clean() -> None:
    """Empty reason placeholders should not become incomplete coverage by themselves."""
    results = _create_result_model(
        file_metadata={"model.bin": {"scan_outcome_reason": "", "scan_outcome_reasons": []}},
    )

    assert determine_exit_code(results) == 0


def test_exit_code_empty_results():
    """Test exit code with minimal results structure."""
    results = _create_result_model(files_scanned=0)
    assert determine_exit_code(results) == 2  # Changed: no files scanned means exit code 2


def test_exit_code_no_files_scanned():
    """Test exit code 2 when no files are scanned."""
    results = _create_result_model(files_scanned=0)
    assert determine_exit_code(results) == 2


def test_exit_code_dry_run_no_files_scanned_success() -> None:
    """Dry-run previews should succeed even when no local files are scanned."""
    results = _create_result_model(files_scanned=0)
    cast(Any, results).dry_run = True
    assert determine_exit_code(results) == 0


def test_exit_code_dry_run_operational_error_still_errors() -> None:
    """Dry-run mode should not mask operational failures."""
    results = _create_result_model(files_scanned=0, has_errors=True)
    cast(Any, results).dry_run = True
    assert determine_exit_code(results) == 2


def test_exit_code_no_files_scanned_with_issues():
    """Security findings should still return exit code 1 even with zero scanned files."""
    results = _create_result_model(
        files_scanned=0,
        issues=[
            Issue(
                message="Path traversal outside scanned directory",
                severity=IssueSeverity.CRITICAL,
                location="link.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 1


def test_exit_code_no_files_scanned_with_info_only_issues():
    """Benign zero-file scans should keep exit code 2 when only informational issues exist."""
    results = _create_result_model(
        files_scanned=0,
        issues=[
            Issue(
                message="No supported model files found",
                severity=IssueSeverity.INFO,
                location="",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 2


def test_exit_code_files_scanned_clean():
    """Test exit code 0 when files are scanned and clean."""
    results = _create_result_model(files_scanned=5)
    assert determine_exit_code(results) == 0


def test_exit_code_files_scanned_with_issues():
    """Test exit code 1 when files are scanned with issues."""
    results = _create_result_model(
        files_scanned=5,
        issues=[
            Issue(
                message="Security issue",
                severity=IssueSeverity.WARNING,
                location="test.pkl",
                timestamp=0.0,
                why=None,
                type=None,
            ),
        ],
    )
    assert determine_exit_code(results) == 1


def test_exit_code_file_scan_failure(tmp_path: Path) -> None:
    """Return exit code 2 when an exception occurs during file scan."""
    test_file = tmp_path / "bad.pkl"
    test_file.write_text("data")

    with patch("modelaudit.core.scan_file", side_effect=RuntimeError("boom")):
        results = scan_model_directory_or_file(str(test_file))

    # Errors during scan set has_errors=True and success=False
    assert getattr(results, "has_errors", False) is True
    assert results.success is False
    # Error should be recorded in issues (severity doesn't affect exit code)
    assert len(results.issues) > 0
    assert any("error" in issue.message.lower() for issue in results.issues)
    # Exit code 2 indicates operational errors
    assert determine_exit_code(results) == 2


def test_scan_result_warning_message_without_operational_flag_keeps_exit_code_1(tmp_path: Path) -> None:
    """Warning findings keep exit 1 even when a bare failed scan is normalized as incomplete."""
    test_file = tmp_path / "malicious.pkl"
    test_file.write_bytes(b"payload")

    scan_result = ScanResult(scanner_name="pickle")
    scan_result.add_check(
        name="Dangerous Pattern Detection",
        passed=False,
        message="Suspicious global reference detected",
        severity=IssueSeverity.WARNING,
        location=str(test_file),
    )
    scan_result.add_check(
        name="Pickle Format Validation",
        passed=False,
        message="Unable to parse pickle file: ValueError",
        severity=IssueSeverity.WARNING,
        location=str(test_file),
        details={"exception_type": "ValueError"},
    )
    scan_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=scan_result):
        results = scan_model_directory_or_file(str(test_file))

    assert results.has_errors is False
    assert results.success is False
    assert determine_exit_code(results) == 1


def test_scan_result_operational_flag_keeps_exit_code_2(tmp_path: Path) -> None:
    """Explicit operational-error metadata should drive exit code 2 without message parsing."""
    test_file = tmp_path / "timeout.pkl"
    test_file.write_bytes(b"payload")

    scan_result = ScanResult(scanner_name="pickle")
    scan_result.add_check(
        name="Scan Timeout Check",
        passed=False,
        message="Scan timeout: simulated timeout",
        severity=IssueSeverity.INFO,
        location=str(test_file),
    )
    scan_result.metadata["operational_error"] = True
    scan_result.metadata["operational_error_reason"] = "scan_timeout"
    scan_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=scan_result):
        results = scan_model_directory_or_file(str(test_file))

    assert results.has_errors is True
    assert results.success is False
    assert determine_exit_code(results) == 2


def test_scan_result_operational_flag_with_security_and_incomplete_keeps_exit_code_2(tmp_path: Path) -> None:
    """Explicit operational failures outrank security findings even with incomplete metadata."""
    test_file = tmp_path / "timeout-danger.pkl"
    test_file.write_bytes(b"payload")

    scan_result = ScanResult(scanner_name="pickle")
    scan_result.add_issue(
        "Dangerous pickle global: os.system",
        severity=IssueSeverity.WARNING,
        location=str(test_file),
    )
    scan_result.add_check(
        name="Scan Timeout Check",
        passed=False,
        message="Scan timeout: simulated timeout",
        severity=IssueSeverity.INFO,
        location=str(test_file),
        details={"timeout": 1},
    )
    scan_result.metadata["operational_error"] = True
    scan_result.metadata["operational_error_reason"] = "scan_timeout"
    scan_result.metadata["analysis_incomplete"] = True
    scan_result.metadata["scan_outcome"] = "inconclusive"
    scan_result.metadata["scan_outcome_reasons"] = ["opcode_budget_exceeded"]
    scan_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=scan_result):
        results = scan_model_directory_or_file(str(test_file))

    assert results.has_errors is True
    assert results.success is False
    assert results.file_metadata[str(test_file)]["analysis_incomplete"] is True
    assert any(issue.severity == IssueSeverity.WARNING for issue in results.issues)
    assert determine_exit_code(results) == 2


def test_scan_result_info_only_failed_scan_without_outcome_fails_closed(tmp_path: Path) -> None:
    """Bare success=False results should become inconclusive instead of exiting clean."""
    test_file = tmp_path / "trailing.npy"
    test_file.write_bytes(b"payload")

    scan_result = ScanResult(scanner_name="numpy")
    scan_result.add_issue(
        "Object-dtype payload contains trailing bytes after the embedded pickle stream",
        severity=IssueSeverity.INFO,
        location=str(test_file),
    )
    scan_result.finish(success=False)

    with patch("modelaudit.core.scan_file", return_value=scan_result):
        results = scan_model_directory_or_file(str(test_file))

    metadata = results.file_metadata[str(test_file)]
    assert metadata["scan_outcome"] == "inconclusive"
    assert "scanner_reported_unsuccessful_without_outcome" in metadata["scan_outcome_reasons"]
    assert results.has_errors is False
    assert results.success is False
    assert determine_exit_code(results) == 2


def test_scan_result_inconclusive_with_security_finding_keeps_exit_code_1(tmp_path: Path) -> None:
    """Security findings should outrank incomplete coverage for exit code, not aggregate success."""
    test_file = tmp_path / "budget-danger.pkl"
    test_file.write_bytes(b"payload")

    scan_result = ScanResult(scanner_name="pickle")
    scan_result.add_check(
        name="Post-Budget Global Reference Scan",
        passed=False,
        message="Dangerous reference found beyond opcode budget: os.system",
        severity=IssueSeverity.CRITICAL,
        location=str(test_file),
    )
    scan_result.metadata["scan_outcome"] = "inconclusive"
    scan_result.metadata["scan_outcome_reasons"] = ["opcode_budget_exceeded"]
    scan_result.finish(success=True)

    with patch("modelaudit.core.scan_file", return_value=scan_result):
        results = scan_model_directory_or_file(str(test_file))

    assert results.has_errors is False
    assert results.success is False
    assert determine_exit_code(results) == 1


def test_scan_model_directory_or_file_inconclusive_pickle_budget_returns_exit_code_2(tmp_path: Path) -> None:
    """Opcode-budget truncation without findings should surface as an inconclusive exit-code 2."""
    test_file = tmp_path / "budget.pkl"
    test_file.write_bytes(b"\x80\x02" + (b"K\x010" * 512) + b".")

    results = scan_model_directory_or_file(str(test_file), max_opcodes=32)

    metadata = results.file_metadata[str(test_file)]
    assert metadata["scan_outcome"] == "inconclusive"
    assert "opcode_budget_exceeded" in metadata["scan_outcome_reasons"]
    assert results.has_errors is False
    assert results.success is False
    assert determine_exit_code(results) == 2


def test_directory_total_size_limit_returns_exit_code_2(tmp_path: Path) -> None:
    """Early directory termination from max_total_size should fail closed."""
    for filename, payload in [
        ("a.pkl", {"data": "x" * 100}),
        ("b.pkl", {"data": "y" * 100}),
        ("c.pkl", {"data": "z" * 100}),
    ]:
        path = tmp_path / filename
        path.write_bytes(pickle.dumps(payload))

    results = scan_model_directory_or_file(str(tmp_path), max_total_size=150, cache_enabled=False)

    assert results.files_scanned == 2
    assert results.success is False
    assert results.has_errors is True
    assert determine_exit_code(results) == 2
    assert any(
        issue.message == "Scan terminated early due to total size limit"
        and issue.details.get("analysis_incomplete") is True
        for issue in results.issues
    )
