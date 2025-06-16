import json
import logging
from pathlib import Path

import pytest

from modelaudit.scanners.base import IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import ManifestScanner


def test_manifest_scanner_json():
    """Test the manifest scanner with a JSON file."""
    # Create a temporary JSON file
    test_file = "config.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "A test model",
        "config": {
            "input_shape": [224, 224, 3],
            "output_shape": [1000],
            "file_path": "/path/to/model/weights.h5",
            "api_key": "secret_key_12345",
        },
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(manifest_content, f)

        # Create scanner with blacklist patterns
        scanner = ManifestScanner(
            config={"blacklist_patterns": ["unsafe", "malicious"]},
        )

        # Test can_handle
        assert scanner.can_handle(test_file) is True

        # Test scan
        result = scanner.scan(test_file)

        # Verify scan completed successfully
        assert result.success is True

        # Check that suspicious keys were detected
        suspicious_keys = [
            issue.details.get("key", "")
            for issue in result.issues
            if hasattr(issue, "details") and "key" in issue.details
        ]
        assert any("file_path" in key for key in suspicious_keys)
        assert any("api_key" in key for key in suspicious_keys)

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_blacklist():
    """Test the manifest scanner with blacklisted terms."""
    # Create a temporary JSON file with a blacklisted term
    test_file = "model_card.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "This is an UNSAFE model that should be flagged",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(manifest_content, f)

        # Create scanner with blacklist patterns
        scanner = ManifestScanner(
            config={"blacklist_patterns": ["unsafe", "malicious"]},
        )

        # Test scan
        result = scanner.scan(test_file)

        # Verify scan completed successfully
        assert result.success is True

        # Check that blacklisted term was detected
        blacklist_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0
        assert any(issue.severity == IssueSeverity.ERROR for issue in blacklist_issues)

        # Verify the specific blacklisted term was identified
        blacklisted_terms = [
            issue.details.get("blacklisted_term", "")
            for issue in blacklist_issues
            if hasattr(issue, "details")
        ]
        assert "unsafe" in blacklisted_terms

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_case_insensitive_blacklist():
    """Test that blacklist matching is case-insensitive."""
    # Create a temporary file with mixed-case blacklisted term
    test_file = "inference_config.json"

    try:
        with Path(test_file).open("w") as f:
            f.write('{"model": "This is a MaLiCiOuS model"}')

        # Create scanner with lowercase blacklist pattern
        scanner = ManifestScanner(config={"blacklist_patterns": ["malicious"]})

        # Test scan
        result = scanner.scan(test_file)

        # Check that the mixed-case term was detected
        blacklist_issues = [
            issue
            for issue in result.issues
            if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_yaml():
    """Test the manifest scanner with a YAML file."""
    # Skip this test - YAML files are no longer supported after whitelist changes
    pytest.skip("YAML files are no longer supported by manifest scanner whitelist")


def test_manifest_scanner_nested_structures():
    """Test the manifest scanner with nested structures."""
    # Create a temporary JSON file with nested structures
    test_file = "model_index.json"
    manifest_content = {
        "model": {
            "name": "nested_model",
            "config": {
                "layers": [
                    {"name": "layer1", "type": "conv2d"},
                    {"name": "layer2", "type": "lambda", "code": "x => x * 2"},
                ],
            },
        },
        "deployment": {
            "environments": [
                {"name": "prod", "url": "https://api.example.com/models"},
                {"name": "dev", "url": "http://localhost:8000"},
            ],
        },
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(manifest_content, f)

        # Create scanner
        scanner = ManifestScanner()

        # Test scan
        result = scanner.scan(test_file)

        # Verify scan completed successfully
        assert result.success is True

        # Check that suspicious keys were detected in nested structures
        suspicious_keys = [
            issue.details.get("key", "")
            for issue in result.issues
            if hasattr(issue, "details")
        ]
        assert any("url" in key for key in suspicious_keys)
        assert any("code" in key for key in suspicious_keys)

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_parse_file_logs_warning(caplog, capsys):
    """Ensure parsing errors log warnings without stdout output."""
    scanner = ManifestScanner()

    with caplog.at_level(logging.WARNING, logger="modelaudit.scanners"):
        result = ScanResult(scanner.name)
        content = scanner._parse_file("nonexistent.json", ".json", result)

    assert content is None
    assert any(
        "Error parsing file nonexistent.json" in record.getMessage()
        for record in caplog.records
    )
    assert capsys.readouterr().out == ""
    assert any(issue.severity == IssueSeverity.DEBUG for issue in result.issues)
