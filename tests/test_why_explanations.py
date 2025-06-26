"""Tests for the 'why' explanations feature."""

import pickle
import tempfile

from modelaudit.explanations import (
    COMMON_MESSAGE_EXPLANATIONS,
    TF_OP_EXPLANATIONS,
    get_import_explanation,
    get_message_explanation,
    get_opcode_explanation,
    get_tf_op_explanation,
)
from modelaudit.scanners.base import Issue, IssueSeverity, ScanResult
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
    assert issue_dict["why"] == "This is dangerous because it can execute arbitrary code."


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
            if ("os" in issue.message.lower() or "posix" in issue.message.lower()) and issue.why is not None
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
        "issues": [
            {
                "message": "Dangerous import: os.system",
                "severity": "critical",
                "location": "test.pkl",
                "why": "The 'os' module provides direct access to operating system functions.",
            },
        ],
    }

    # Format the output
    output = format_text_output(test_results)

    # Check that the output includes the "Why:" label
    assert "Why:" in output

    # Check for the explanation text, accounting for line wrapping
    # Remove ANSI codes and normalize whitespace
    clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)
    normalized_output = " ".join(clean_output.split())
    assert "operating system functions" in normalized_output


def test_tf_op_explanation_function():
    """Test the get_tf_op_explanation function directly."""
    # Test valid TensorFlow operation
    explanation = get_tf_op_explanation("PyFunc")
    assert explanation is not None
    assert "executes arbitrary Python code" in explanation
    assert "TensorFlow graph" in explanation

    # Test another critical operation
    explanation = get_tf_op_explanation("ShellExecute")
    assert explanation is not None
    assert "shell commands" in explanation
    assert "compromising the host system" in explanation

    # Test file operation
    explanation = get_tf_op_explanation("ReadFile")
    assert explanation is not None
    assert "arbitrary files" in explanation
    assert "exfiltrate secrets" in explanation

    # Test invalid operation
    explanation = get_tf_op_explanation("NonExistentOp")
    assert explanation is None


def test_all_tf_operations_have_explanations():
    """Test that all TensorFlow operations in TF_OP_EXPLANATIONS have valid explanations."""
    from modelaudit.suspicious_symbols import SUSPICIOUS_OPS

    # Verify all SUSPICIOUS_OPS have explanations
    for op in SUSPICIOUS_OPS:
        explanation = get_tf_op_explanation(op)
        assert explanation is not None, f"Missing explanation for TensorFlow operation: {op}"
        assert isinstance(explanation, str), f"Explanation for {op} must be a string"
        assert len(explanation) > 10, f"Explanation for {op} is too short: {explanation}"

    # Verify all explanations are for operations in SUSPICIOUS_OPS
    for op in TF_OP_EXPLANATIONS:
        assert op in SUSPICIOUS_OPS, f"TF_OP_EXPLANATIONS contains {op} which is not in SUSPICIOUS_OPS"


def test_tf_explanation_quality():
    """Test that TensorFlow explanations meet quality standards."""
    for op_name, explanation in TF_OP_EXPLANATIONS.items():
        # Should be non-empty string
        assert isinstance(explanation, str), f"Explanation for {op_name} must be a string"
        assert len(explanation) > 20, f"Explanation for {op_name} is too short"

        # Should mention security risk or attack vector
        security_keywords = [
            "attack",
            "malicious",
            "abuse",
            "exploit",
            "dangerous",
            "risk",
            "compromise",
            "execute",
            "system",
            "arbitrary",
            "vulnerabilities",
        ]
        assert any(keyword in explanation.lower() for keyword in security_keywords), (
            f"Explanation for {op_name} should mention security risks: {explanation}"
        )

        # Should be properly formatted (no trailing/leading whitespace)
        assert explanation == explanation.strip(), f"Explanation for {op_name} has improper whitespace"


def test_tf_explanation_categories():
    """Test that TensorFlow explanations are properly categorized by risk level."""
    # Critical risk operations (code execution)
    critical_ops = ["PyFunc", "PyCall", "ExecuteOp", "ShellExecute", "SystemConfig"]
    for op in critical_ops:
        explanation = get_tf_op_explanation(op)
        assert explanation is not None
        # Should mention code execution or system compromise
        critical_keywords = ["execute", "code", "system", "shell", "commands"]
        assert any(keyword in explanation.lower() for keyword in critical_keywords), (
            f"Critical operation {op} should mention code execution risks"
        )

    # File system operations
    file_ops = ["ReadFile", "WriteFile", "Save", "SaveV2", "MergeV2Checkpoints"]
    for op in file_ops:
        explanation = get_tf_op_explanation(op)
        assert explanation is not None
        # Should mention file operations
        file_keywords = ["file", "write", "read", "save", "overwrite"]
        assert any(keyword in explanation.lower() for keyword in file_keywords), (
            f"File operation {op} should mention file system risks"
        )

    # Data processing operations
    data_ops = ["DecodeRaw", "DecodeJpeg", "DecodePng"]
    for op in data_ops:
        explanation = get_tf_op_explanation(op)
        assert explanation is not None
        # Should mention data processing risks
        data_keywords = ["decode", "data", "malicious", "exploit", "vulnerabilities"]
        assert any(keyword in explanation.lower() for keyword in data_keywords), (
            f"Data operation {op} should mention data processing risks"
        )


def test_tf_explanation_unified_architecture():
    """Test that TensorFlow explanations use the unified get_explanation architecture."""
    from modelaudit.explanations import get_explanation

    # Test that get_tf_op_explanation uses get_explanation internally
    op_name = "PyFunc"
    direct_explanation = get_tf_op_explanation(op_name)
    unified_explanation = get_explanation("tf_op", op_name)

    assert direct_explanation == unified_explanation, "get_tf_op_explanation should use get_explanation internally"

    # Test all TF operations through unified interface
    for op_name in TF_OP_EXPLANATIONS:
        explanation = get_explanation("tf_op", op_name)
        assert explanation is not None, f"get_explanation should work for tf_op category with {op_name}"
        assert explanation == TF_OP_EXPLANATIONS[op_name], (
            f"Unified explanation should match direct lookup for {op_name}"
        )


def test_common_message_explanations_coverage():
    """Test that all COMMON_MESSAGE_EXPLANATIONS patterns work correctly."""
    # Test that all defined patterns have explanations
    assert len(COMMON_MESSAGE_EXPLANATIONS) > 0, "Should have common message explanations defined"

    for prefix, explanation in COMMON_MESSAGE_EXPLANATIONS.items():
        assert explanation, f"Explanation for '{prefix}' should not be empty"
        assert len(explanation) > 20, f"Explanation for '{prefix}' should be substantial"


def test_get_message_explanation_exact_matches():
    """Test get_message_explanation with exact prefix matches."""
    test_cases = [
        ("Maximum ZIP nesting depth", "zip bombs"),
        ("ZIP file contains too many entries", "zip bomb"),
        ("Archive entry", "path traversal"),
        ("Symlink", "path traversal"),
        ("File too small", "truncated"),
        ("Not a valid zip file", "malformed"),
        ("File too large", "denial-of-service"),
        ("Too many", "overwhelm"),
        ("Error scanning", "corrupted files"),
        ("Decompressed size too large", "compression bombs"),
        # New ML-specific patterns
        ("Custom objects found", "arbitrary Python code"),
        ("External reference", "sensitive data"),
        ("Lambda layer", "arbitrary Python code"),
        ("Custom layer", "untrusted code"),
        ("Module not installed", "supply chain"),
        ("Import error", "malicious modules"),
        ("Missing metadata", "tampered models"),
        ("Invalid metadata", "file tampering"),
    ]

    for prefix, expected_keyword in test_cases:
        explanation = get_message_explanation(prefix)
        assert explanation is not None, f"Should have explanation for '{prefix}'"
        assert expected_keyword.lower() in explanation.lower(), (
            f"Explanation for '{prefix}' should contain '{expected_keyword}'"
        )


def test_get_message_explanation_prefix_matching():
    """Test that get_message_explanation works with prefix matching."""
    test_cases = [
        ("Maximum ZIP nesting depth exceeded at level 10", True),
        ("ZIP file contains too many entries: 50000 found", True),
        ("Archive entry would extract to ../../../etc/passwd", True),
        ("Symlink pointing outside safe directory", True),
        ("File too small: expected 1000, got 50 bytes", True),
        ("Not a valid zip file: header corrupted", True),
        ("File too large: 2GB exceeds 1GB limit", True),
        ("Too many suspicious imports detected", True),
        ("Error scanning model: pickle corruption", True),
        ("Decompressed size too large: 10GB from 1MB", True),
        ("Random message that doesn't match any pattern", False),
        ("Different file format detected", False),
    ]

    for message, should_have_explanation in test_cases:
        explanation = get_message_explanation(message)
        if should_have_explanation:
            assert explanation is not None, f"Should have explanation for message: '{message}'"
        else:
            assert explanation is None, f"Should not have explanation for message: '{message}'"


def test_scan_result_auto_explanation_integration():
    """Test that ScanResult.add_issue automatically adds explanations from COMMON_MESSAGE_EXPLANATIONS."""
    result = ScanResult("test_scanner")

    # Test messages that should get automatic explanations
    test_messages = [
        "Maximum ZIP nesting depth exceeded",
        "File too large: 500MB",
        "Error scanning corrupted model",
        "Custom message without explanation",
    ]

    for message in test_messages:
        result.add_issue(message, severity=IssueSeverity.WARNING)

    # Check that the right issues got explanations
    issues_with_explanation = [issue for issue in result.issues if issue.why is not None]
    issues_without_explanation = [issue for issue in result.issues if issue.why is None]

    # Should have 3 with explanations, 1 without
    assert len(issues_with_explanation) == 3
    assert len(issues_without_explanation) == 1
    assert issues_without_explanation[0].message == "Custom message without explanation"


def test_scan_result_explicit_why_overrides_auto():
    """Test that explicit 'why' parameter overrides automatic explanation lookup."""
    result = ScanResult("test_scanner")

    # Add an issue with a message that would normally get an auto-explanation,
    # but provide an explicit 'why' parameter
    explicit_why = "This is a custom explanation that should override the default"
    result.add_issue(
        "Maximum ZIP nesting depth exceeded",
        severity=IssueSeverity.WARNING,
        why=explicit_why,
    )

    # The explicit explanation should be used, not the automatic one
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.why == explicit_why

    # Verify it's not the automatic explanation
    auto_explanation = get_message_explanation("Maximum ZIP nesting depth exceeded")
    assert issue.why != auto_explanation


def test_common_message_explanations_security_focus():
    """Test that all common message explanations focus on security implications."""
    security_keywords = [
        "malicious",
        "attack",
        "security",
        "exploit",
        "dangerous",
        "overwhelm",
        "exhaust",
        "crash",
        "compromise",
        "overwrite",
        "traversal",
        "bomb",
        "denial-of-service",
        "tampering",
        "corrupt",
        "vulnerabilities",
        "arbitrary",
        "untrusted",
        "bypass",
        "hide",
        "disguised",
        "spoofing",
        "tampered",
        "execution",
        "execute",
    ]

    for prefix, explanation in COMMON_MESSAGE_EXPLANATIONS.items():
        # Each explanation should contain at least one security-focused keyword
        explanation_lower = explanation.lower()
        has_security_keyword = any(keyword in explanation_lower for keyword in security_keywords)
        assert has_security_keyword, f"Explanation for '{prefix}' should focus on security implications: {explanation}"


def test_message_explanation_serialization():
    """Test that issues with automatic explanations serialize correctly."""
    result = ScanResult("test_scanner")
    result.add_issue("File too large: exceeds limit", severity=IssueSeverity.WARNING)

    # Test dictionary serialization
    result_dict = result.to_dict()
    assert len(result_dict["issues"]) == 1
    issue_dict = result_dict["issues"][0]
    assert "why" in issue_dict
    assert "denial-of-service" in issue_dict["why"].lower()

    # Test JSON serialization
    json_str = result.to_json()
    assert '"why"' in json_str
    assert "denial-of-service" in json_str.lower()


def test_context_aware_explanations():
    """Test that explanations can be enhanced with context information."""
    from modelaudit.explanations import get_message_explanation

    # Test ML model context enhancement
    basic_explanation = get_message_explanation("Custom objects found")
    ml_context_explanation = get_message_explanation("Custom objects found", context="pickle_scanner")

    assert basic_explanation is not None
    assert ml_context_explanation is not None
    # Context-aware explanation should be more specific
    assert len(ml_context_explanation) > len(basic_explanation)
    assert "pickle-based formats" in ml_context_explanation.lower()

    # Test archive context enhancement
    basic_archive_explanation = get_message_explanation("Archive entry would extract outside")
    archive_context_explanation = get_message_explanation("Archive entry would extract outside", context="zip_scanner")

    assert basic_archive_explanation is not None
    assert archive_context_explanation is not None
    # Should get enhanced explanation for archive context
    assert "ML model deployments" in archive_context_explanation


def test_scan_result_context_integration():
    """Test that ScanResult passes scanner context for enhanced explanations."""
    result = ScanResult("pickle_scanner")
    result.add_issue("Custom objects found in model")

    # Should get the enhanced pickle-specific explanation
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.why is not None
    assert "pickle-based formats" in issue.why.lower()


def test_ml_specific_message_patterns():
    """Test that new ML-specific message patterns work correctly."""
    ml_messages = [
        "Custom objects found in TensorFlow model",
        "External reference to /etc/passwd detected",
        "Lambda layer with suspicious code",
        "Custom layer implementation found",
        "Module not installed: malicious_package",
        "Import error: cannot load suspicious_module",
        "Missing metadata in model file",
        "Invalid metadata: corrupted JSON",
        "Unexpected metadata field: __exec__",
    ]

    for message in ml_messages:
        explanation = get_message_explanation(message)
        assert explanation is not None, f"Should have explanation for ML message: '{message}'"
        # All ML explanations should mention security implications
        assert any(
            keyword in explanation.lower()
            for keyword in [
                "malicious",
                "attack",
                "security",
                "compromise",
                "dangerous",
                "exploit",
                "arbitrary",
                "untrusted",
                "execute",
                "execution",
                "vulnerabilities",
            ]
        ), f"ML explanation should focus on security: '{explanation}'"
