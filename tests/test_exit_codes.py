"""Tests specifically for exit code logic."""

from unittest.mock import patch

from modelaudit.core import determine_exit_code, scan_model_directory_or_file

# Ensure models are rebuilt for forward references
from modelaudit.models import ModelAuditResultModel, rebuild_models
from modelaudit.scanners.base import Issue, IssueSeverity

rebuild_models()


def _create_result_model(**kwargs):
    """Helper function to create ModelAuditResultModel with sensible defaults."""
    defaults = {
        "success": True,
        "has_errors": False,
        "issues": [],
        "files_scanned": 1,
        "bytes_scanned": 100,
        "duration": 1.0,
        "checks": [],
        "start_time": 0.0,
        "total_checks": 0,
        "passed_checks": 0,
        "failed_checks": 0,
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
            Issue(message="Debug info", severity=IssueSeverity.DEBUG, location="test.pkl", timestamp=0.0),
        ]
    )
    assert determine_exit_code(results) == 0


def test_exit_code_security_issues():
    """Test exit code 1 for security issues found."""
    results = _create_result_model(
        issues=[
            Issue(message="Suspicious operation", severity=IssueSeverity.WARNING, location="test.pkl", timestamp=0.0),
        ]
    )
    assert determine_exit_code(results) == 1


def test_exit_code_security_errors():
    """Test exit code 1 for security errors found."""
    results = _create_result_model(
        issues=[
            Issue(
                message="Malicious code detected", severity=IssueSeverity.CRITICAL, location="test.pkl", timestamp=0.0
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
            ),
            Issue(
                message="Also found suspicious code",
                severity=IssueSeverity.WARNING,
                location="test2.pkl",
                timestamp=0.0,
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
            Issue(message="Debug info", severity=IssueSeverity.DEBUG, location="test.pkl", timestamp=0.0),
            Issue(message="Info message", severity=IssueSeverity.INFO, location="test.pkl", timestamp=0.0),
            Issue(
                message="Warning about something", severity=IssueSeverity.WARNING, location="test.pkl", timestamp=0.0
            ),
        ]
    )
    # Should return 1 because there are non-debug issues
    assert determine_exit_code(results) == 1


def test_exit_code_info_level_issues():
    """Test exit code 0 for info level issues (INFO is not a security problem)."""
    results = _create_result_model(
        issues=[
            Issue(message="Information about model", severity=IssueSeverity.INFO, location="test.pkl", timestamp=0.0),
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
    """Test exit code 2 when no files are scanned even with issues."""
    results = _create_result_model(
        files_scanned=0,
        issues=[
            Issue(message="Some issue", severity=IssueSeverity.WARNING, location="test.pkl", timestamp=0.0),
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
            Issue(message="Security issue", severity=IssueSeverity.WARNING, location="test.pkl", timestamp=0.0),
        ],
    )
    assert determine_exit_code(results) == 1


def test_exit_code_file_scan_failure(tmp_path):
    """Return exit code 2 when an exception occurs during file scan."""
    test_file = tmp_path / "bad.pkl"
    test_file.write_text("data")

    with patch("modelaudit.core.scan_file", side_effect=RuntimeError("boom")):
        results = scan_model_directory_or_file(str(test_file))

    assert getattr(results, "has_errors", False) is True
    assert results.success is False
    assert any(getattr(issue, "severity", None) == IssueSeverity.CRITICAL for issue in results.issues)
    assert determine_exit_code(results) == 2
