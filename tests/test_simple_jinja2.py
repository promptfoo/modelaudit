#!/usr/bin/env python3

import json
import os
import shutil
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

        # Get warning issues too
        warning_issues = [i for i in result.issues if i.severity == IssueSeverity.WARNING]

        # Test assertions
        assert result.success, "Scan should complete successfully"
        assert len(result.issues) > 0, "Should detect issues"
        # CVE patterns are detected as WARNING (HIGH risk level = WARNING severity)
        assert len(warning_issues) > 0 or len(critical_issues) > 0, "Should have warning or critical issues"

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


def test_liquidai_template_no_false_positives():
    """Test that LiquidAI-style template with bracket notation doesn't cause false positives"""
    scanner = Jinja2TemplateScanner()

    # Real template snippet from LiquidAI/LFM2-1.2B that was causing false positives
    config = {
        "tokenizer_class": "LlamaTokenizer",
        "chat_template": (
            "{{- bos_token -}}"
            '{%- set ns = namespace(system_prompt="") -%}'
            '{%- if messages[0]["role"] == "system" -%}'
            '  {%- set ns.system_prompt = messages[0]["content"] -%}'
            "{%- endif -%}"
            "{%- for message in messages -%}"
            '  {{- "<|im_start|>" + message["role"] + "\\n" -}}'
            '  {%- set content = message["content"] -%}'
            '  {%- if message["role"] == "tool" -%}'
            '    {%- set content = "<|tool_response_start|>" + content + "<|tool_response_end|>" -%}'
            "  {%- endif -%}"
            '  {{- content + "<|im_end|>\\n" -}}'
            "{%- endfor -%}"
        ),
    }

    # Create temp file with proper name and huggingface path for context detection
    tmpdir = tempfile.mkdtemp()
    hf_dir = os.path.join(tmpdir, "huggingface", "LiquidAI", "LFM2-1.2B")
    os.makedirs(hf_dir)
    path = os.path.join(hf_dir, "tokenizer_config.json")
    try:
        with open(path, "w") as f:
            json.dump(config, f)

        result = scanner.scan(path)

        print(f"LiquidAI template scan success: {result.success}")
        print(f"LiquidAI template total issues: {len(result.issues)}")

        # Check severity breakdown
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        warning_issues = [i for i in result.issues if i.severity == IssueSeverity.WARNING]
        info_issues = [i for i in result.issues if i.severity == IssueSeverity.INFO]

        print(f"  Critical: {len(critical_issues)}")
        print(f"  Warnings: {len(warning_issues)}")
        print(f"  Info: {len(info_issues)}")

        # Pattern types detected
        if result.issues:
            patterns = {i.details.get("pattern_type") for i in result.issues if i.details}
            print(f"  Pattern types: {patterns}")

        assert result.success, "Scan should complete successfully"
        assert len(critical_issues) == 0, "Should not have critical issues for legitimate template"
        assert len(warning_issues) == 0, "Should not have warnings for legitimate bracket notation like ['role']"

        print("✅ LiquidAI template test PASSED - no false positives!")

    finally:
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    test_cve_detection()
    test_benign_template()
    test_liquidai_template_no_false_positives()
    print("\n🎉 All tests PASSED!")
