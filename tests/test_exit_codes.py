"""Tests specifically for exit code logic."""

from modelaudit.core import determine_exit_code


def test_exit_code_clean_scan():
    """Test exit code 0 for clean scan with no issues."""
    results = {"success": True, "has_errors": False, "issues": [], "files_scanned": 1}
    assert determine_exit_code(results) == 0


def test_exit_code_clean_scan_with_debug_issues():
    """Test exit code 0 for scan with only debug issues."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "test.pkl"},
        ],
        "files_scanned": 1,
    }
    assert determine_exit_code(results) == 0


def test_exit_code_security_issues():
    """Test exit code 1 for security issues found."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {
                "message": "Suspicious operation",
                "severity": "warning",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 1,
    }
    assert determine_exit_code(results) == 1


def test_exit_code_security_errors():
    """Test exit code 1 for security errors found."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {
                "message": "Malicious code detected",
                "severity": "error",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 1,
    }
    assert determine_exit_code(results) == 1


def test_exit_code_operational_errors():
    """Test exit code 2 for operational errors."""
    results = {
        "success": False,
        "has_errors": True,
        "issues": [
            {
                "message": "Error during scan: File not found",
                "severity": "error",
                "location": "test.pkl",
            },
        ],
    }
    assert determine_exit_code(results) == 2


def test_exit_code_mixed_issues():
    """Test that operational errors take precedence over security issues."""
    results = {
        "success": False,
        "has_errors": True,
        "issues": [
            {
                "message": "Error during scan: Scanner crashed",
                "severity": "error",
                "location": "test.pkl",
            },
            {
                "message": "Also found suspicious code",
                "severity": "warning",
                "location": "test2.pkl",
            },
        ],
    }
    # Operational errors (exit code 2) should take precedence
    # over security issues (exit code 1)
    assert determine_exit_code(results) == 2


def test_exit_code_mixed_severity():
    """Test with mixed severity levels (no operational errors)."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {"message": "Debug info", "severity": "debug", "location": "test.pkl"},
            {"message": "Info message", "severity": "info", "location": "test.pkl"},
            {
                "message": "Warning about something",
                "severity": "warning",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 1,
    }
    # Should return 1 because there are non-debug issues
    assert determine_exit_code(results) == 1


def test_exit_code_info_level_issues():
    """Test exit code 0 for info level issues (INFO is not a security problem)."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {
                "message": "Information about model",
                "severity": "info",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 1,
    }
    assert determine_exit_code(results) == 0  # INFO level should not trigger exit code 1


def test_exit_code_empty_results():
    """Test exit code with minimal results structure."""
    results = {}
    assert determine_exit_code(results) == 2  # Changed: no files scanned means exit code 2


def test_exit_code_no_files_scanned():
    """Test exit code 2 when no files are scanned."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [],
        "files_scanned": 0,
    }
    assert determine_exit_code(results) == 2


def test_exit_code_no_files_scanned_with_issues():
    """Test exit code 2 when no files are scanned even with issues."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {
                "message": "Some issue",
                "severity": "warning",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 0,
    }
    assert determine_exit_code(results) == 2


def test_exit_code_files_scanned_clean():
    """Test exit code 0 when files are scanned and clean."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [],
        "files_scanned": 5,
    }
    assert determine_exit_code(results) == 0


def test_exit_code_files_scanned_with_issues():
    """Test exit code 1 when files are scanned with issues."""
    results = {
        "success": True,
        "has_errors": False,
        "issues": [
            {
                "message": "Security issue",
                "severity": "warning",
                "location": "test.pkl",
            },
        ],
        "files_scanned": 5,
    }
    assert determine_exit_code(results) == 1
