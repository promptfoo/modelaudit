"""Test detection of webbrowser module as a critical security issue."""

import pickle
import tempfile
from pathlib import Path

from modelaudit.scanners.pickle_scanner import PickleScanner


def test_webbrowser_open_detection():
    """Test that webbrowser.open is detected as CRITICAL."""
    # Create a malicious pickle that uses webbrowser.open
    malicious_code = """
import webbrowser
webbrowser.open("https://malicious.site/pwned")
"""

    # Create a pickle file with webbrowser.open reference
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Create a simple pickle that imports webbrowser
        pickle.dump({"code": malicious_code}, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should have at least one critical issue
        assert len(critical_issues) > 0, "No critical issues found for webbrowser"

        # Check that webbrowser is mentioned in critical issues
        webbrowser_found = any("webbrowser" in issue.message.lower() for issue in critical_issues)
        assert webbrowser_found, "webbrowser not found in critical issues"

    finally:
        Path(temp_path).unlink()


def test_webbrowser_pattern_in_raw_bytes():
    """Test that raw webbrowser pattern is detected as CRITICAL."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Write pickle with webbrowser.open reference
        f.write(b"\x80\x02cwebbrowser\nopen\nq\x00X\x20\x00\x00\x00https://example.com\nq\x01K\x00\x88\x87q\x02Rq\x03.")
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues
        critical_issues = [issue for issue in result.issues if str(issue.severity) == "IssueSeverity.CRITICAL"]

        # Should detect webbrowser as critical
        assert len(critical_issues) > 0, "No critical issues found for raw webbrowser bytes"

        # Verify webbrowser is in the critical messages
        webbrowser_critical = any("webbrowser" in issue.message.lower() for issue in critical_issues)
        assert webbrowser_critical, "webbrowser pattern not detected as critical"

    finally:
        Path(temp_path).unlink()


def test_webbrowser_methods_detection():
    """Test detection of various webbrowser methods."""
    methods = ["open", "open_new", "open_new_tab"]

    for method in methods:
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            # Create pickle referencing webbrowser method
            pickle_data = pickle.dumps({"module": "webbrowser", "method": method, "url": "https://test.com"})
            f.write(pickle_data)
            temp_path = f.name

        try:
            scanner = PickleScanner()
            result = scanner.scan(temp_path)

            # Should have issues (at least warnings)
            assert len(result.issues) > 0, f"No issues found for webbrowser.{method}"

            # Check severity levels
            has_critical_or_warning = any("webbrowser" in issue.message.lower() for issue in result.issues)
            assert has_critical_or_warning, f"webbrowser.{method} not detected"

        finally:
            Path(temp_path).unlink()


def test_webbrowser_not_false_positive_in_comments():
    """Test that webbrowser in documentation/comments is not flagged."""
    # Create a safe pickle with webbrowser only in a comment string
    safe_data = {"documentation": "This model does not use webbrowser# Safe comment", "config": {"safe": True}}

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump(safe_data, f)
        temp_path = f.name

    try:
        scanner = PickleScanner()
        result = scanner.scan(temp_path)

        # Check for critical issues mentioning webbrowser
        critical_webbrowser_issues = [
            issue
            for issue in result.issues
            if str(issue.severity) == "IssueSeverity.CRITICAL" and "webbrowser" in issue.message.lower()
        ]

        # Should not flag webbrowser in documentation as critical
        # (The semantic analysis should mark it as safe)
        assert len(critical_webbrowser_issues) == 0, "False positive: webbrowser in documentation flagged as critical"

    finally:
        Path(temp_path).unlink()


if __name__ == "__main__":
    test_webbrowser_open_detection()
    test_webbrowser_pattern_in_raw_bytes()
    test_webbrowser_methods_detection()
    test_webbrowser_not_false_positive_in_comments()
    print("All webbrowser detection tests passed!")
