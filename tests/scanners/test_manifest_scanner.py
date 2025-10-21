import json
import logging
from pathlib import Path

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import ManifestScanner


def test_manifest_scanner_blacklist():
    """Test the manifest scanner with blacklisted terms."""
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
            issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in blacklist_issues)

        # Verify the specific blacklisted term was identified
        blacklisted_terms = [
            issue.details.get("blacklisted_term", "") for issue in blacklist_issues if hasattr(issue, "details")
        ]
        assert "unsafe" in blacklisted_terms

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_case_insensitive_blacklist():
    """Test that blacklist matching is case-insensitive."""
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
            issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
        ]
        assert len(blacklist_issues) > 0

    finally:
        # Clean up
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_no_blacklist_clean_file():
    """Test that clean files with no blacklist patterns pass."""
    test_file = "config.json"
    clean_config = {
        "model_type": "bert",
        "hidden_size": 768,
        "architectures": ["BertModel"],
        "_name_or_path": "bert-base-uncased",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(clean_config, f)

        scanner = ManifestScanner(config={"blacklist_patterns": ["malware", "trojan"]})
        result = scanner.scan(test_file)

        assert result.success is True

        # Should have a passed blacklist check
        passed_checks = [check for check in result.checks if check.status == CheckStatus.PASSED]
        assert any("Blacklist" in check.name for check in passed_checks)

        # Should have no critical issues
        critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_model_name_policy():
    """Test model name policy checking."""
    test_file = "config.json"
    config_with_model_name = {
        "model_name": "legitimate_model",
        "model_type": "bert",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_model_name, f)

        scanner = ManifestScanner(config={"blacklist_patterns": []})
        result = scanner.scan(test_file)

        assert result.success is True

        # Should have model name policy checks
        model_name_checks = [check for check in result.checks if "Model Name Policy" in check.name]
        assert len(model_name_checks) > 0

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_metadata_extraction():
    """Test that model metadata is extracted from config.json files."""
    test_file = "config.json"
    huggingface_config = {
        "_name_or_path": "bert-base-uncased",
        "model_type": "bert",
        "architectures": ["BertModel"],
        "hidden_size": 768,
        "num_hidden_layers": 12,
        "num_attention_heads": 12,
        "vocab_size": 30522,
        "transformers_version": "4.35.0",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(huggingface_config, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Check that model metadata was extracted
        assert "model_info" in result.metadata
        model_info = result.metadata["model_info"]
        assert model_info["model_type"] == "bert"
        assert model_info["architectures"] == ["BertModel"]
        assert model_info["hidden_size"] == 768
        assert model_info["num_layers"] == 12
        assert model_info["num_heads"] == 12
        assert model_info["vocab_size"] == 30522
        assert model_info["framework_version"] == "4.35.0"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_license_extraction():
    """Test that license information is extracted."""
    test_file = "model_card.json"
    config_with_license = {
        "model_name": "test_model",
        "license": "apache-2.0",
        "version": "1.0.0",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_license, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True
        assert "license" in result.metadata
        assert result.metadata["license"] == "apache-2.0"

    finally:
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
    assert any("Error parsing file nonexistent.json" in record.getMessage() for record in caplog.records)
    assert capsys.readouterr().out == ""
    assert any(issue.severity == IssueSeverity.DEBUG for issue in result.issues)


def test_manifest_scanner_yaml():
    """Test the manifest scanner with a YAML file."""
    # Skip this test - YAML files are no longer supported after whitelist changes
    pytest.skip("YAML files are no longer supported by manifest scanner whitelist")


def test_manifest_scanner_can_handle():
    """Test that scanner correctly identifies supported files."""
    scanner = ManifestScanner()

    # Should handle HuggingFace configs
    assert scanner.can_handle("config.json") is True
    assert scanner.can_handle("generation_config.json") is True
    assert scanner.can_handle("model_index.json") is True

    # Should not handle tokenizer configs (excluded)
    assert scanner.can_handle("tokenizer_config.json") is False

    # Should not handle non-ML configs
    assert scanner.can_handle("package.json") is False
    assert scanner.can_handle("tsconfig.json") is False
