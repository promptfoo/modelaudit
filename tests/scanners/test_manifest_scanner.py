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

    # Test files with expected can_handle results
    test_cases = [
        # HuggingFace/ML configs - should be handled
        ("config.json", True),
        ("generation_config.json", True),
        ("model_index.json", True),
        # Files containing "config.json" substring also match
        ("tokenizer_config.json", True),
        # Non-ML configs - should not be handled
        ("package.json", False),
        ("data.json", False),
    ]

    created_files = []
    try:
        for filename, expected in test_cases:
            Path(filename).write_text("{}")
            created_files.append(filename)
            assert scanner.can_handle(filename) is expected, f"{filename} expected {expected}"
    finally:
        for filename in created_files:
            Path(filename).unlink(missing_ok=True)


def test_manifest_scanner_suspicious_url_shortener():
    """Test that URL shorteners in config values are flagged."""
    test_file = "config.json"
    config_with_shortener = {
        "model_type": "bert",
        "download_url": "https://bit.ly/abc123",
        "architectures": ["BertModel"],
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_shortener, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should have a suspicious URL check that failed
        url_checks = [check for check in result.checks if "Suspicious URL" in check.name]
        assert len(url_checks) > 0
        assert any(check.status == CheckStatus.FAILED for check in url_checks)

        # Verify the URL was detected
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert any("bit.ly" in c.details.get("suspicious_domain", "") for c in failed_url_checks)

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_suspicious_tunnel_service():
    """Test that tunnel services (ngrok, localtunnel) in config values are flagged."""
    test_file = "config.json"
    config_with_tunnel = {
        "model_type": "gpt2",
        "callback_url": "https://abc123.ngrok.io/webhook",
        "hidden_size": 768,
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_tunnel, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should have a suspicious URL check that failed
        url_checks = [check for check in result.checks if "Suspicious URL" in check.name]
        assert len(url_checks) > 0
        assert any(check.status == CheckStatus.FAILED for check in url_checks)

        # Verify ngrok was detected
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert any("ngrok.io" in c.details.get("suspicious_domain", "") for c in failed_url_checks)

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_trusted_urls_not_flagged():
    """Test that URLs from trusted domains (huggingface, github, etc.) are NOT flagged."""
    test_file = "config.json"
    config_with_trusted_urls = {
        "model_type": "bert",
        "_name_or_path": "https://huggingface.co/bert-base-uncased",
        "repository": "https://github.com/huggingface/transformers",
        "homepage": "https://pytorch.org/models",
        "weights": "https://s3.amazonaws.com/models/bert.bin",
        "storage": "https://storage.googleapis.com/models/bert",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_trusted_urls, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should have NO URL checks that failed (all trusted domains)
        url_checks = [check for check in result.checks if "URL" in check.name]
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert len(failed_url_checks) == 0, f"Unexpected failed checks: {failed_url_checks}"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_untrusted_domain_flagged():
    """Test that URLs from untrusted/unknown domains ARE flagged."""
    test_file = "config.json"
    config_with_untrusted_url = {
        "model_type": "bert",
        "download_url": "https://totally-legit-models.com/model.bin",
        "callback": "https://unknown-server.net/webhook",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_untrusted_url, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should flag untrusted domains
        url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert len(failed_url_checks) == 2, f"Expected 2 untrusted URLs, got {len(failed_url_checks)}"

        # Verify reason is set correctly
        for check in failed_url_checks:
            assert check.details.get("reason") == "untrusted_domain"

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_nested_suspicious_url():
    """Test that suspicious URLs in nested config structures are detected."""
    test_file = "config.json"
    config_with_nested_url = {
        "model_type": "bert",
        "training": {
            "callbacks": {
                "webhook_url": "https://tinyurl.com/malicious",
            }
        },
        "pipelines": [
            {"name": "inference", "endpoint": "https://localtunnel.me/api"},
        ],
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_nested_url, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should detect both suspicious URLs
        url_checks = [check for check in result.checks if "Suspicious URL" in check.name]
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert len(failed_url_checks) == 2

        # Verify both domains were detected
        detected_domains = {c.details.get("suspicious_domain", "") for c in failed_url_checks}
        assert "tinyurl.com" in detected_domains
        assert "localtunnel.me" in detected_domains

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()


def test_manifest_scanner_duplicate_urls_not_repeated():
    """Test that the same suspicious URL appearing multiple times is only reported once."""
    test_file = "config.json"
    config_with_duplicate_urls = {
        "model_type": "bert",
        "primary_url": "https://bit.ly/same123",
        "backup_url": "https://bit.ly/same123",
        "fallback_url": "https://bit.ly/same123",
    }

    try:
        with Path(test_file).open("w") as f:
            json.dump(config_with_duplicate_urls, f)

        scanner = ManifestScanner()
        result = scanner.scan(test_file)

        assert result.success is True

        # Should only have ONE suspicious URL check (deduplication)
        url_checks = [check for check in result.checks if "Suspicious URL" in check.name]
        failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
        assert len(failed_url_checks) == 1

    finally:
        test_file_path = Path(test_file)
        if test_file_path.exists():
            test_file_path.unlink()
