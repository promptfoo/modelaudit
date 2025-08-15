"""Test detection of runpy module as a critical security issue."""

import pickle
import tempfile
from pathlib import Path

from modelaudit.scanners.pickle_scanner import PickleScanner


def test_runpy_run_module_detection():
    """Test that runpy.run_module is detected as CRITICAL."""
    # Create a malicious pickle that uses runpy.run_module
    malicious_code = """
import runpy
runpy.run_module('os', run_name='__main__')
"""

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump({"code": malicious_code}, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should have at least one critical issue
        assert len(critical_issues) > 0, "No critical issues found for runpy"

        # Check that runpy is mentioned in critical issues
        runpy_found = any("runpy" in issue.message.lower() for issue in critical_issues)
        assert runpy_found, "runpy not found in critical issues"

    finally:
        Path(temp_path).unlink()


def test_runpy_run_path_detection():
    """Test that runpy.run_path is detected as CRITICAL."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Create pickle with runpy.run_path
        code = """
import runpy
runpy.run_path('/path/to/malicious.py')
"""
        pickle.dump({"code": code}, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should detect runpy as critical
        assert len(critical_issues) > 0, "No critical issues found for runpy.run_path"

        # Verify runpy is in the critical messages
        runpy_critical = any("runpy" in issue.message.lower() for issue in critical_issues)
        assert runpy_critical, "runpy.run_path not detected as critical"

    finally:
        Path(temp_path).unlink()


def test_runpy_pattern_in_raw_bytes():
    """Test that raw runpy pattern is detected as CRITICAL."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Write pickle with runpy reference
        f.write(b"\x80\x02crunpy\nrun_module\nq\x00X\x02\x00\x00\x00os\nq\x01\x85q\x02Rq\x03.")
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should detect runpy as critical
        assert len(critical_issues) > 0, "No critical issues found for raw runpy bytes"

        # Verify runpy is in the critical messages
        runpy_critical = any("runpy" in issue.message.lower() for issue in critical_issues)
        assert runpy_critical, "runpy pattern not detected as critical"

    finally:
        Path(temp_path).unlink()


def test_runpy_not_false_positive_in_comments():
    """Test that runpy in documentation/comments is not flagged as CRITICAL."""
    # Create a safe pickle with runpy only in a comment string
    safe_data = {"documentation": "This model does not use runpy# Safe comment", "config": {"safe": True}}

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump(safe_data, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues mentioning runpy
        critical_runpy_issues = [
            issue
            for issue in result.issues
            if str(issue.severity) == "IssueSeverity.CRITICAL" and "runpy" in issue.message.lower()
        ]

        # Should not flag runpy in documentation as critical
        # (The semantic analysis should mark it as safe)
        assert len(critical_runpy_issues) == 0, "False positive: runpy in documentation flagged as critical"

    finally:
        Path(temp_path).unlink()


if __name__ == "__main__":
    test_runpy_run_module_detection()
    test_runpy_run_path_detection()
    test_runpy_pattern_in_raw_bytes()
    test_runpy_not_false_positive_in_comments()
    print("All runpy detection tests passed!")
