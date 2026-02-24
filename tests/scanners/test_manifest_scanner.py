import json
import logging

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import ManifestScanner


def test_manifest_scanner_blacklist(tmp_path):
    """Test the manifest scanner with blacklisted terms."""
    test_file = tmp_path / "model_card.json"
    manifest_content = {
        "model_name": "test_model",
        "version": "1.0.0",
        "description": "This is an UNSAFE model that should be flagged",
    }

    test_file.write_text(json.dumps(manifest_content))

    # Create scanner with blacklist patterns
    scanner = ManifestScanner(
        config={"blacklist_patterns": ["unsafe", "malicious"]},
    )

    # Test scan
    result = scanner.scan(str(test_file))

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


def test_manifest_scanner_case_insensitive_blacklist(tmp_path):
    """Test that blacklist matching is case-insensitive."""
    test_file = tmp_path / "inference_config.json"

    test_file.write_text('{"model": "This is a MaLiCiOuS model"}')

    # Create scanner with lowercase blacklist pattern
    scanner = ManifestScanner(config={"blacklist_patterns": ["malicious"]})

    # Test scan
    result = scanner.scan(str(test_file))

    # Check that the mixed-case term was detected
    blacklist_issues = [
        issue for issue in result.issues if hasattr(issue, "message") and "Blacklisted term" in issue.message
    ]
    assert len(blacklist_issues) > 0


def test_manifest_scanner_no_blacklist_clean_file(tmp_path):
    """Test that clean files with no blacklist patterns pass."""
    test_file = tmp_path / "config.json"
    clean_config = {
        "model_type": "bert",
        "hidden_size": 768,
        "architectures": ["BertModel"],
        "_name_or_path": "bert-base-uncased",
    }

    test_file.write_text(json.dumps(clean_config))

    scanner = ManifestScanner(config={"blacklist_patterns": ["malware", "trojan"]})
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have a passed blacklist check
    passed_checks = [check for check in result.checks if check.status == CheckStatus.PASSED]
    assert any("Blacklist" in check.name for check in passed_checks)

    # Should have no critical issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_manifest_scanner_model_name_policy(tmp_path):
    """Test model name policy checking."""
    test_file = tmp_path / "config.json"
    config_with_model_name = {
        "model_name": "legitimate_model",
        "model_type": "bert",
    }

    test_file.write_text(json.dumps(config_with_model_name))

    scanner = ManifestScanner(config={"blacklist_patterns": []})
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have model name policy checks
    model_name_checks = [check for check in result.checks if "Model Name Policy" in check.name]
    assert len(model_name_checks) > 0


def test_manifest_scanner_metadata_extraction(tmp_path):
    """Test that model metadata is extracted from config.json files."""
    test_file = tmp_path / "config.json"
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

    test_file.write_text(json.dumps(huggingface_config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

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


def test_manifest_scanner_license_extraction(tmp_path):
    """Test that license information is extracted."""
    test_file = tmp_path / "model_card.json"
    config_with_license = {
        "model_name": "test_model",
        "license": "apache-2.0",
        "version": "1.0.0",
    }

    test_file.write_text(json.dumps(config_with_license))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True
    assert "license" in result.metadata
    assert result.metadata["license"] == "apache-2.0"


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


def test_manifest_scanner_can_handle(tmp_path):
    """Test that scanner correctly identifies supported files."""
    scanner = ManifestScanner()

    # Create actual files for testing (scanner requires files to exist)
    (tmp_path / "config.json").write_text('{"model_type": "test"}')
    (tmp_path / "generation_config.json").write_text("{}")
    (tmp_path / "model_index.json").write_text("{}")
    (tmp_path / "tokenizer_config.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "tsconfig.json").write_text("{}")

    # Should handle HuggingFace configs
    assert scanner.can_handle(str(tmp_path / "config.json")) is True
    assert scanner.can_handle(str(tmp_path / "generation_config.json")) is True
    assert scanner.can_handle(str(tmp_path / "model_index.json")) is True

    # Should not handle tokenizer configs (excluded)
    assert scanner.can_handle(str(tmp_path / "tokenizer_config.json")) is False

    # Should not handle non-ML configs
    assert scanner.can_handle(str(tmp_path / "package.json")) is False
    assert scanner.can_handle(str(tmp_path / "tsconfig.json")) is False


def test_manifest_scanner_url_shortener_flagged(tmp_path):
    """Test that URL shorteners are flagged (not in allowlist)."""
    test_file = tmp_path / "config.json"
    config_with_shortener = {
        "model_type": "bert",
        "download_url": "https://bit.ly/abc123",
        "architectures": ["BertModel"],
    }

    test_file.write_text(json.dumps(config_with_shortener))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag URL shortener as untrusted domain
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1
    assert "bit.ly" in failed_url_checks[0].details.get("url", "")


def test_manifest_scanner_tunnel_service_flagged(tmp_path):
    """Test that tunnel services (ngrok, localtunnel) are flagged (not in allowlist)."""
    test_file = tmp_path / "config.json"
    config_with_tunnel = {
        "model_type": "gpt2",
        "callback_url": "https://abc123.ngrok.io/webhook",
        "hidden_size": 768,
    }

    test_file.write_text(json.dumps(config_with_tunnel))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag tunnel service as untrusted domain
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1
    assert "ngrok.io" in failed_url_checks[0].details.get("url", "")


def test_manifest_scanner_trusted_urls_not_flagged(tmp_path):
    """Test that URLs from trusted domains (huggingface, github, etc.) are NOT flagged as untrusted."""
    test_file = tmp_path / "config.json"
    config_with_trusted_urls = {
        "model_type": "bert",
        "_name_or_path": "https://huggingface.co/bert-base-uncased",
        "repository": "https://github.com/huggingface/transformers",
        "homepage": "https://pytorch.org/models",
        "weights": "https://s3.amazonaws.com/models/bert.bin",
        "storage": "https://storage.googleapis.com/models/bert",
    }

    test_file.write_text(json.dumps(config_with_trusted_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should have NO "Untrusted URL Check" failures (all are trusted domains)
    # Note: "Cloud Storage URL Detection" may still flag these as INFO for visibility
    untrusted_url_checks = [
        c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED
    ]
    assert len(untrusted_url_checks) == 0, f"Unexpected untrusted URL checks: {untrusted_url_checks}"


def test_manifest_scanner_untrusted_domain_flagged(tmp_path):
    """Test that URLs from untrusted/unknown domains ARE flagged."""
    test_file = tmp_path / "config.json"
    config_with_untrusted_url = {
        "model_type": "bert",
        "download_url": "https://totally-legit-models.com/model.bin",
        "callback": "https://unknown-server.net/webhook",
    }

    test_file.write_text(json.dumps(config_with_untrusted_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should flag untrusted domains
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2, f"Expected 2 untrusted URLs, got {len(failed_url_checks)}"

    # Verify URLs were detected
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("totally-legit-models.com" in url for url in detected_urls)
    assert any("unknown-server.net" in url for url in detected_urls)


def test_manifest_scanner_domain_substring_bypass_flagged(tmp_path):
    """URLs with trusted-domain substrings in the path/host should still be flagged."""
    test_file = tmp_path / "config.json"
    config_with_spoofed_url = {
        "model_type": "bert",
        "download_url": "https://evil.example/huggingface.co/backdoor.bin",
        "mirror_url": "https://huggingface.co.evil.example/model.bin",
    }

    test_file.write_text(json.dumps(config_with_spoofed_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2, f"Expected 2 untrusted URLs, got {len(failed_url_checks)}"

    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("evil.example/huggingface.co" in url for url in detected_urls)
    assert any("huggingface.co.evil.example" in url for url in detected_urls)


def test_manifest_scanner_nested_untrusted_url(tmp_path):
    """Test that untrusted URLs in nested config structures are detected."""
    test_file = tmp_path / "config.json"
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

    test_file.write_text(json.dumps(config_with_nested_url))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should detect both untrusted URLs
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 2

    # Verify both URLs were detected
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("tinyurl.com" in url for url in detected_urls)
    assert any("localtunnel.me" in url for url in detected_urls)


def test_manifest_scanner_duplicate_urls_not_repeated(tmp_path):
    """Test that the same untrusted URL appearing multiple times is only reported once."""
    test_file = tmp_path / "config.json"
    config_with_duplicate_urls = {
        "model_type": "bert",
        "primary_url": "https://bit.ly/same123",
        "backup_url": "https://bit.ly/same123",
        "fallback_url": "https://bit.ly/same123",
    }

    test_file.write_text(json.dumps(config_with_duplicate_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    # Should only have ONE untrusted URL check (deduplication)
    url_checks = [check for check in result.checks if "Untrusted URL" in check.name]
    failed_url_checks = [c for c in url_checks if c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 1
