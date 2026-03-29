"""Tests specifically for exit code logic."""

from typing import Any
from unittest.mock import patch

from modelaudit.core import determine_exit_code, scan_model_directory_or_file

# Ensure models are rebuilt for forward references
from modelaudit.models import ModelAuditResultModel, rebuild_models
from modelaudit.scanners.base import Issue, IssueSeverity, ScanResult

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


def test_exit_code_empty_results():
    """Test exit code with minimal results structure."""
    results = _create_result_model(files_scanned=0)
    assert determine_exit_code(results) == 2  # Changed: no files scanned means exit code 2


def test_exit_code_no_files_scanned():
    """Test exit code 2 when no files are scanned."""
    results = _create_result_model(files_scanned=0)
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


def test_exit_code_file_scan_failure(tmp_path):
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


def test_scan_result_warning_message_without_operational_flag_keeps_exit_code_1(tmp_path) -> None:
    """Warning findings should not become exit code 2 just because the message looks like a parse error."""
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
    assert results.success is True
    assert determine_exit_code(results) == 1


def test_scan_result_operational_flag_keeps_exit_code_2(tmp_path) -> None:
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


def test_scan_result_info_only_failed_scan_without_operational_flag_keeps_exit_code_0(tmp_path) -> None:
    """Informational failed scans should stay clean without explicit operational metadata."""
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

    assert results.has_errors is False
    assert results.success is True
    assert determine_exit_code(results) == 0
