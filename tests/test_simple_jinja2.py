#!/usr/bin/env python3

import json
import os
import tempfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.jinja2_template_scanner import Jinja2TemplateScanner


def test_cve_detection():
    """Simple test for CVE-2024-34359 detection"""
    scanner = Jinja2TemplateScanner()

    # CVE-2024-34359 payload
    config = {
        "tokenizer_class": "LlamaTokenizer",
        "chat_template": (
            "{% for c in [].__class__.__base__.__subclasses__() %}"
            "{% if c.__name__ == 'catch_warnings' %}"
            "{{ c()._module.__builtins__['__import__']('os').system('touch /tmp/retr0reg') }}"
            "{% endif %}{% endfor %}"
        ),
    }

    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)

        result = scanner.scan(path)

        print(f"Scan success: {result.success}")
        print(f"Total issues: {len(result.issues)}")

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        print(f"Critical issues: {len(critical_issues)}")

        # Check for expected patterns
        patterns = {i.details.get("pattern_type") for i in result.issues}
        print(f"Detected patterns: {patterns}")

        # Test assertions
        assert result.success, "Scan should complete successfully"
        assert len(result.issues) > 0, "Should detect issues"
        assert len(critical_issues) > 0, "Should have critical issues"

        expected_patterns = {"object_traversal", "global_access", "control_flow"}
        found_patterns = expected_patterns.intersection(patterns)
        assert len(found_patterns) > 0, f"Should detect expected patterns. Found: {patterns}"

        print("✅ CVE-2024-34359 detection test PASSED")

    finally:
        os.unlink(path)


def test_benign_template():
    """Test that benign templates don't cause false positives"""
    scanner = Jinja2TemplateScanner()

    config = {
        "tokenizer_class": "GPT2Tokenizer",
        "chat_template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
    }

    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)

        result = scanner.scan(path)

        print(f"Benign scan success: {result.success}")
        print(f"Benign total issues: {len(result.issues)}")

        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        print(f"Benign critical issues: {len(critical_issues)}")

        assert result.success, "Scan should complete successfully"
        assert len(critical_issues) == 0, "Should not have critical issues for benign template"

        print("✅ Benign template test PASSED")

    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_cve_detection()
    test_benign_template()
    print("\n🎉 All tests PASSED!")
