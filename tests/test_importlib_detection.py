"""Test detection of importlib module as a critical security issue."""

import pickle
import tempfile
from pathlib import Path

from modelaudit.scanners.pickle_scanner import PickleScanner


def test_importlib_import_module_detection():
    """Test that importlib.import_module is detected as CRITICAL."""
    # Create a malicious pickle that uses importlib.import_module
    malicious_code = """
import importlib
malicious = importlib.import_module('os')
malicious.system('echo pwned')
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
        assert len(critical_issues) > 0, "No critical issues found for importlib"

        # Check that importlib is mentioned in critical issues
        importlib_found = any("importlib" in issue.message.lower() for issue in critical_issues)
        assert importlib_found, "importlib not found in critical issues"

    finally:
        Path(temp_path).unlink()


def test_importlib_pattern_in_raw_bytes():
    """Test that raw importlib pattern is detected as CRITICAL."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Write pickle with importlib.import_module reference
        # This is a simplified pickle that references importlib.import_module
        f.write(b"\x80\x02cimportlib\nimport_module\nq\x00X\x02\x00\x00\x00os\nq\x01\x85q\x02Rq\x03.")
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should detect importlib as critical
        assert len(critical_issues) > 0, "No critical issues found for raw importlib bytes"

        # Verify importlib is in the critical messages
        importlib_critical = any("importlib" in issue.message.lower() for issue in critical_issues)
        assert importlib_critical, "importlib pattern not detected as critical"

    finally:
        Path(temp_path).unlink()


def test_importlib_various_methods():
    """Test detection of various importlib methods."""
    test_cases = [
        ("import_module", "os"),
        ("reload", "sys"),
        ("find_loader", "subprocess"),
        ("load_module", "socket"),
    ]

    for method, module in test_cases:
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            # Create pickle referencing importlib method
            data = {"loader": "importlib", "method": method, "target": module}
            pickle.dump(data, f)
            temp_path = f.name

        try:
            scanner = PickleScanner()
            result = scanner.scan(temp_path)

            # Should have issues (at least warnings)
            assert len(result.issues) > 0, f"No issues found for importlib.{method}"

            # Check if importlib is detected
            has_importlib_issue = any("importlib" in issue.message.lower() for issue in result.issues)
            assert has_importlib_issue, f"importlib.{method} not detected"

        finally:
            Path(temp_path).unlink()


def test_importlib_machinery_detection():
    """Test detection of importlib.machinery usage."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Create pickle with importlib.machinery reference
        code = """
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("malicious", "/path/to/malicious.py")
module = loader.load_module()
"""
        pickle.dump({"code": code}, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Should detect issues
        assert len(result.issues) > 0, "No issues found for importlib.machinery"

        # Check for importlib detection
        importlib_detected = any("importlib" in issue.message.lower() for issue in result.issues)
        assert importlib_detected, "importlib.machinery not detected"

    finally:
        Path(temp_path).unlink()


def test_importlib_util_detection():
    """Test detection of importlib.util usage."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Create pickle with importlib.util reference
        code = """
import importlib.util
spec = importlib.util.spec_from_file_location("malicious", "/path/to/malicious.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
"""
        pickle.dump({"code": code}, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Should detect issues
        assert len(result.issues) > 0, "No issues found for importlib.util"

        # Check for importlib detection
        importlib_detected = any("importlib" in issue.message.lower() for issue in result.issues)
        assert importlib_detected, "importlib.util not detected"

    finally:
        Path(temp_path).unlink()


def test_importlib_not_false_positive_in_comments():
    """Test that importlib in documentation/comments is not flagged as CRITICAL."""
    # Create a safe pickle with importlib only in a comment string
    safe_data = {"documentation": "This model does not use importlib# Safe comment", "config": {"safe": True}}

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump(safe_data, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues mentioning importlib
        critical_importlib_issues = [
            issue
            for issue in result.issues
            if str(issue.severity) == "IssueSeverity.CRITICAL" and "importlib" in issue.message.lower()
        ]

        # Should not flag importlib in documentation as critical
        # (The semantic analysis should mark it as safe)
        assert len(critical_importlib_issues) == 0, "False positive: importlib in documentation flagged as critical"

    finally:
        Path(temp_path).unlink()


if __name__ == "__main__":
    test_importlib_import_module_detection()
    test_importlib_pattern_in_raw_bytes()
    test_importlib_various_methods()
    test_importlib_machinery_detection()
    test_importlib_util_detection()
    test_importlib_not_false_positive_in_comments()
    print("All importlib detection tests passed!")
