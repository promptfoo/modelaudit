import json
import logging
from pathlib import Path

import pytest

import modelaudit.scanners.manifest_scanner as manifest_scanner_module
from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.manifest_scanner import ManifestScanner, _is_trusted_url_domain


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


def test_manifest_scanner_yaml_not_handled(tmp_path):
    """Test that YAML files are not handled by the manifest scanner."""
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("model_type: bert\nhidden_size: 768\n")

    scanner = ManifestScanner()
    assert scanner.can_handle(str(yaml_file)) is False


def test_manifest_scanner_yml_not_handled(tmp_path):
    """Test that .yml files are not handled by the manifest scanner."""
    yml_file = tmp_path / "config.yml"
    yml_file.write_text("model_type: gpt2\nhidden_size: 768\n")

    scanner = ManifestScanner()
    assert scanner.can_handle(str(yml_file)) is False


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
        "raw_config": "https://raw.githubusercontent.com/huggingface/transformers/main/config.json",
        "homepage": "https://pytorch.org/models",
        "weights": "https://s3.amazonaws.com/models/bert.bin",
        "storage": "https://storage.googleapis.com/models/bert",
        "dataset_docs": "https://openimages.github.io/dataset/",
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


def test_manifest_scanner_official_registry_subdomains_not_flagged(tmp_path: Path) -> None:
    """Official registry service subdomains should remain trusted."""
    test_file = tmp_path / "config.json"
    config_with_registry_urls = {
        "model_type": "bert",
        "docker_registry": "https://registry-1.docker.io/v2/library/python/manifests/latest",
        "gcr_registry": "https://us.gcr.io/project/image:latest",
    }

    test_file.write_text(json.dumps(config_with_registry_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert failed_url_checks == []


def test_manifest_scanner_broad_hosting_subdomains_flagged(tmp_path):
    """Attacker-controlled subdomains on broad hosting domains should not be trusted."""
    test_file = tmp_path / "config.json"
    config_with_hosting_urls = {
        "model_type": "bert",
        "github_pages": "https://attacker.github.io/model.bin",
        "cloudfront": "https://d111111abcdef8.cloudfront.net/model.bin",
        "googleusercontent": "https://evil.googleusercontent.com/model.bin",
    }

    test_file.write_text(json.dumps(config_with_hosting_urls))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    assert result.success is True

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 3

    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert "https://attacker.github.io/model.bin" in detected_urls
    assert "https://d111111abcdef8.cloudfront.net/model.bin" in detected_urls
    assert "https://evil.googleusercontent.com/model.bin" in detected_urls


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


def test_manifest_scanner_enforces_size_limit(tmp_path):
    """Manifest scans should stop when max_file_read_size is exceeded."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "description": "x" * 64}))

    scanner = ManifestScanner(config={"max_file_read_size": 16})
    result = scanner.scan(str(test_file))

    assert result.success is False
    size_checks = [check for check in result.checks if check.name == "File Size Limit"]
    assert len(size_checks) == 1
    assert size_checks[0].status == CheckStatus.FAILED
    assert result.metadata["file_size"] == test_file.stat().st_size


def test_manifest_scanner_enforces_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manifest scans should stop when the scanner timeout is exceeded."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})

    def expire_timeout(_path: str, _result: ScanResult) -> None:
        scanner.scan_start_time = 0

    monkeypatch.setattr(scanner, "_check_file_for_blacklist", expire_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is True
    timeout_checks = [check for check in result.checks if check.name == "Manifest Scan Timeout"]
    assert len(timeout_checks) == 1
    assert timeout_checks[0].status == CheckStatus.FAILED
    assert timeout_checks[0].severity == IssueSeverity.WARNING


def test_manifest_scanner_blacklist_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in blacklist checks should not be converted to blacklist errors."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1, "blacklist_patterns": ["bert"]})
    timeout_calls = 0

    def raise_on_helper_timeout(*_args: object, **_kwargs: object) -> bool:
        nonlocal timeout_calls
        timeout_calls += 1
        if timeout_calls == 2:
            raise TimeoutError("blacklist helper timed out")
        return False

    monkeypatch.setattr(scanner, "_check_timeout", raise_on_helper_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is True
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]


def test_manifest_scanner_parse_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in manifest parsing should not be converted to parse errors."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})
    monkeypatch.setattr(scanner, "_check_file_for_blacklist", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_cloud_storage_urls", lambda _path, _result: None)

    def raise_timeout(_content: str) -> dict:
        raise TimeoutError("parse helper timed out")

    monkeypatch.setattr(manifest_scanner_module.json, "loads", raise_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is True
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(check.name == "File Parse Error" for check in result.checks)
    assert not any(check.name == "Manifest Parse Attempt" for check in result.checks)


def test_manifest_scanner_cloud_url_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeouts in cloud URL checks should not be swallowed."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert"}))

    scanner = ManifestScanner(config={"timeout": 1})
    timeout_calls = 0

    def raise_on_helper_timeout(*_args: object, **_kwargs: object) -> bool:
        nonlocal timeout_calls
        timeout_calls += 1
        if timeout_calls == 3:
            raise TimeoutError("cloud URL helper timed out")
        return False

    monkeypatch.setattr(scanner, "_check_file_for_blacklist", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_timeout", raise_on_helper_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is True
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(check.name == "Manifest File Scan" for check in result.checks)


def test_manifest_scanner_weak_hash_timeout_reports_only_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timeout overruns after weak-hash analysis should still report a manifest timeout."""
    test_file = tmp_path / "config.json"
    test_file.write_text(json.dumps({"model_type": "bert", "checksum": "e3b0c44298fc1c149afbf4c8996fb924"}))

    scanner = ManifestScanner(config={"timeout": 1})
    monkeypatch.setattr(scanner, "_check_file_for_blacklist", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_cloud_storage_urls", lambda _path, _result: None)
    monkeypatch.setattr(scanner, "_check_model_name_policies", lambda _content, _result: None)
    monkeypatch.setattr(scanner, "_check_suspicious_urls", lambda _content, _result: None)

    def expire_timeout(_content: object, _result: ScanResult) -> None:
        scanner.scan_start_time = 0

    monkeypatch.setattr(scanner, "_check_weak_hashes", expire_timeout)

    result = scanner.scan(str(test_file))

    assert result.success is True
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == ["Manifest Scan Timeout"]
    assert not any(check.name == "Manifest File Scan" for check in result.checks)


# ---------------------------------------------------------------------------
# Unit tests for _is_trusted_url_domain
# ---------------------------------------------------------------------------


class TestIsTrustedUrlDomain:
    """Direct tests for the module-level domain trust function."""

    def test_exact_trusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://github.com/repo") is True
        assert _is_trusted_url_domain("https://huggingface.co/model") is True

    def test_subdomain_of_trusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://raw.githubusercontent.com/f") is True
        assert _is_trusted_url_domain("https://sub.pytorch.org/w") is True

    def test_exact_match_domains_block_subdomains(self) -> None:
        """Subdomains of exact-match hosting domains must NOT be trusted."""
        assert _is_trusted_url_domain("https://attacker.github.io/p") is False
        assert _is_trusted_url_domain("https://evil.cloudfront.net/p") is False
        assert _is_trusted_url_domain("https://evil.googleusercontent.com/p") is False
        assert _is_trusted_url_domain("https://evil.readthedocs.io/p") is False
        assert _is_trusted_url_domain("https://evil.gitbook.io/p") is False
        assert _is_trusted_url_domain("https://evil.streamlit.io/p") is False
        assert _is_trusted_url_domain("https://evil.gradio.app/p") is False
        assert _is_trusted_url_domain("https://evil.fastly.net/p") is False
        assert _is_trusted_url_domain("https://evil.azureedge.net/p") is False
        assert _is_trusted_url_domain("https://evil.sourceforge.net/p") is False
        assert _is_trusted_url_domain("https://evil.quay.io/p") is False

    def test_official_registry_subdomains_trusted(self) -> None:
        assert _is_trusted_url_domain("https://registry-1.docker.io/v2/library/python/manifests/latest") is True
        assert _is_trusted_url_domain("https://us.gcr.io/project/image:latest") is True

    def test_exact_match_domain_itself_trusted(self) -> None:
        """The bare exact-match domain should still be trusted."""
        assert _is_trusted_url_domain("https://github.io/page") is True
        assert _is_trusted_url_domain("https://cloudfront.net/res") is True
        assert _is_trusted_url_domain("https://readthedocs.io/docs") is True

    def test_userinfo_bypass_blocked(self) -> None:
        """URLs with userinfo (user@host) must NOT be trusted."""
        assert _is_trusted_url_domain("https://evil.com@github.com/payload") is False
        assert _is_trusted_url_domain("https://evil.com@huggingface.co/model") is False
        assert _is_trusted_url_domain("https://user:pass@pytorch.org/w") is False

    def test_untrusted_domain(self) -> None:
        assert _is_trusted_url_domain("https://evil-site.com/payload") is False
        assert _is_trusted_url_domain("https://not-github.com/repo") is False

    def test_empty_and_malformed(self) -> None:
        assert _is_trusted_url_domain("") is False
        assert _is_trusted_url_domain("not-a-url") is False
        assert _is_trusted_url_domain("https://") is False

    def test_trailing_dot_normalization(self) -> None:
        assert _is_trusted_url_domain("https://github.com./repo") is True


def test_manifest_scanner_userinfo_url_flagged(tmp_path: Path) -> None:
    """URLs with userinfo should be flagged as untrusted even if hostname is trusted."""
    test_file = tmp_path / "config.json"
    config = {
        "model_type": "bert",
        "download": "https://evil.com@huggingface.co/model.bin",
    }
    test_file.write_text(json.dumps(config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) >= 1
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert any("evil.com@huggingface.co" in u for u in detected_urls)


def test_manifest_scanner_expanded_exact_domains_flagged(tmp_path: Path) -> None:
    """Newly added exact-match domains should flag attacker subdomains."""
    test_file = tmp_path / "config.json"
    config = {
        "model_type": "bert",
        "docs": "https://evil.readthedocs.io/payload",
        "cdn": "https://evil.fastly.net/payload",
        "app": "https://evil.streamlit.io/payload",
    }
    test_file.write_text(json.dumps(config))

    scanner = ManifestScanner()
    result = scanner.scan(str(test_file))

    failed_url_checks = [c for c in result.checks if c.name == "Untrusted URL Check" and c.status == CheckStatus.FAILED]
    assert len(failed_url_checks) == 3
    detected_urls = {c.details.get("url", "") for c in failed_url_checks}
    assert "https://evil.readthedocs.io/payload" in detected_urls
    assert "https://evil.fastly.net/payload" in detected_urls
    assert "https://evil.streamlit.io/payload" in detected_urls
