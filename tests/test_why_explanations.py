"""Tests for the 'why' explanations feature."""

import pickle
import tempfile

from modelaudit.explanations import get_import_explanation, get_opcode_explanation
from modelaudit.scanners.base import Issue, IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner


def test_issue_with_why_field():
    """Test that Issue class accepts and serializes the 'why' field."""
    issue = Issue(
        message="Test security issue",
        severity=IssueSeverity.CRITICAL,
        location="test.pkl",
        why="This is dangerous because it can execute arbitrary code.",
    )

    # Test that the why field is stored
    assert issue.why == "This is dangerous because it can execute arbitrary code."

    # Test serialization includes why field
    issue_dict = issue.to_dict()
    assert "why" in issue_dict
    assert (
        issue_dict["why"] == "This is dangerous because it can execute arbitrary code."
    )


def test_issue_without_why_field():
    """Test that Issue class works without the 'why' field (backward compatibility)."""
    issue = Issue(
        message="Test security issue",
        severity=IssueSeverity.WARNING,
        location="test.pkl",
    )

    # Test that why field is None
    assert issue.why is None

    # Test serialization doesn't include why field when None
    issue_dict = issue.to_dict()
    assert "why" not in issue_dict


def test_explanations_for_dangerous_imports():
    """Test that we have explanations for dangerous imports."""
    # Test some critical imports
    assert get_import_explanation("os") is not None
    assert "system commands" in get_import_explanation("os").lower()

    assert get_import_explanation("subprocess") is not None
    assert "arbitrary command execution" in get_import_explanation("subprocess").lower()

    assert get_import_explanation("eval") is not None
    assert "arbitrary" in get_import_explanation("eval").lower()


def test_explanations_for_opcodes():
    """Test that we have explanations for dangerous opcodes."""
    assert get_opcode_explanation("REDUCE") is not None
    assert "__reduce__" in get_opcode_explanation("REDUCE")

    assert get_opcode_explanation("INST") is not None
    assert "execute code" in get_opcode_explanation("INST").lower()


def test_pickle_scanner_includes_why():
    """Test that pickle scanner includes 'why' explanations for dangerous imports."""
    scanner = PickleScanner()

    # Create a pickle with os.system call
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Create a malicious pickle
        class Evil:
            def __reduce__(self):
                import os

                return (os.system, ("echo pwned",))

        pickle.dump(Evil(), f)
        temp_path = f.name

    try:
        # Scan the file
        result = scanner.scan(temp_path)

        # Find issues with explanations
        issues_with_why = [issue for issue in result.issues if issue.why is not None]

        # We should have at least one issue with a 'why' explanation
        assert len(issues_with_why) > 0

        # Check that at least one issue mentions 'os' or 'posix' and has an explanation
        system_issues = [
            issue
            for issue in result.issues
            if ("os" in issue.message.lower() or "posix" in issue.message.lower())
            and issue.why is not None
        ]
        assert len(system_issues) > 0

        # The explanation should mention system commands or operating system
        assert any("system" in issue.why.lower() for issue in system_issues)

    finally:
        import os

        os.unlink(temp_path)


def test_cli_output_format_includes_why():
    """Test that CLI output formatting includes 'why' explanations."""
    import re

    from modelaudit.cli import format_text_output

    # Create test results with 'why' explanations
    test_results = {
        "duration": 1.5,
        "files_scanned": 1,
        "bytes_scanned": 1024,
        "scanner_names": ["test_scanner"],
        "paths": ["test.pkl"],
        "issues": [
            {
                "message": "Dangerous import: os.system",
                "severity": "critical",
                "location": "test.pkl",
                "why": "The 'os' module provides direct access to operating system functions.",
            }
        ],
    }

    # Format the output
    output = format_text_output(test_results)

    # Check that the output includes the explanation (with 💡 emoji instead of "Why:")
    assert "💡" in output

    # Check for the explanation text, accounting for line wrapping
    # Remove ANSI codes and normalize whitespace
    clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    normalized_output = " ".join(clean_output.split())
    assert "operating system functions" in normalized_output
