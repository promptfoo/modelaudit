"""Tests for metadata scanner."""

import json
import logging
import os
import tempfile
from pathlib import Path

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners import metadata_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.metadata_scanner import MetadataScanner
from modelaudit.utils.helpers import cache_decorator
from tests.cache_lifecycle import IsolatedCacheManager
from tests.helpers.text import LowerCountingText


class TestMetadataScanner:
    """Test metadata scanner functionality."""

    def test_known_secret_format_reuses_lowered_description(self) -> None:
        description = LowerCountingText("OpenAI API Key")

        assert MetadataScanner._is_known_secret_format(description) is True
        assert description.lower_calls == 1

    def test_can_handle_text_metadata(self):
        """Test that scanner handles text metadata files only."""
        scanner = MetadataScanner()

        # Should handle README and documentation files
        assert scanner.can_handle("README")
        assert scanner.can_handle("readme")
        assert scanner.can_handle("README.md")
        assert scanner.can_handle("readme.txt")
        assert scanner.can_handle("model_card.md")
        assert scanner.can_handle("model_card.txt")
        assert scanner.can_handle("model-index.yml")
        assert scanner.can_handle("model-index.yaml")

        # Should NOT handle config files (handled by ManifestScanner)
        assert not scanner.can_handle("config.json")
        assert not scanner.can_handle("tokenizer_config.json")
        assert not scanner.can_handle("generation_config.json")

    def test_cannot_handle_other_files(self):
        """Test that scanner rejects non-metadata files."""
        scanner = MetadataScanner()

        assert not scanner.can_handle("model.pkl")
        assert not scanner.can_handle("pytorch_model.bin")
        assert not scanner.can_handle("data.txt")
        assert not scanner.can_handle("random.json")

    def test_scan_valid_readme(self) -> None:
        """Test scanning valid README file."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# My Model\n\nThis is a clean README with no security issues.\n")

            result = scanner.scan(str(readme_path))

        assert result.scanner_name == "metadata"
        assert len(result.issues) == 0  # Clean README should have no issues

    def test_metadata_read_failure_is_inconclusive_not_security_finding(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Direct metadata scans should fail closed without a fabricated security issue."""
        readme_path = tmp_path / "README.md"
        readme_path.write_text("# Model Card\n\nThis README is benign.\n")

        def fail_read(*_args: object, **_kwargs: object) -> object:
            raise OSError("simulated metadata read failure")

        monkeypatch.setattr(metadata_scanner, "open", fail_read, raising=False)

        result = MetadataScanner().scan(str(readme_path))

        assert result.success is False
        assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert result.metadata["scan_outcome_reasons"] == ["metadata_read_failed"]
        assert result.metadata["operational_error"] is True
        assert result.metadata["operational_error_reason"] == "metadata_read_failed"
        read_checks = [check for check in result.checks if check.name == "Metadata File Read"]
        assert len(read_checks) == 1
        assert read_checks[0].severity == IssueSeverity.INFO
        assert read_checks[0].rule_code is None
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)

    def test_metadata_invalid_utf8_is_operational_not_security_finding(self, tmp_path: Path) -> None:
        readme_path = tmp_path / "README.md"
        readme_path.write_bytes(b"# Model Card\n\ninvalid text: \xff\n")

        direct = MetadataScanner().scan(str(readme_path))
        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata["operational_error_reason"] == "metadata_read_failed"
        read_check = next(check for check in direct.checks if check.name == "Metadata File Read")
        assert read_check.details["exception_type"] == "UnicodeDecodeError"
        assert direct.bytes_scanned == readme_path.stat().st_size
        assert read_check.severity == IssueSeverity.INFO
        assert read_check.rule_code is None

    def test_metadata_permission_failure_is_operational_after_preflight(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        readme_path = tmp_path / "README.md"
        readme_path.write_text("# Model Card\n", encoding="utf-8")
        real_access = os.access

        def inaccessible_owned_path(path: str, mode: int) -> bool:
            return False if path == str(readme_path) else real_access(path, mode)

        monkeypatch.setattr("modelaudit.scanners.base.os.access", inaccessible_owned_path)

        with caplog.at_level(logging.INFO, logger="modelaudit.scanners"):
            direct = MetadataScanner().scan(str(readme_path))
        assert not any(record.levelno >= logging.CRITICAL for record in caplog.records)
        assert direct.success is False
        assert direct.metadata["operational_error_reason"] == "metadata_read_failed"
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)

    def test_metadata_read_failure_bypasses_stale_clean_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        metadata_path = tmp_path / "model-index.yml"
        metadata_path.write_text("model-index:\n- name: clean-model\n" + "x" * 11_000, encoding="utf-8")
        cache_dir = tmp_path / "cache"

        with IsolatedCacheManager(reset_cache_manager):
            with monkeypatch.context() as warm_cache:
                warm_cache.setattr(
                    cache_decorator,
                    "should_bypass_cache_for_read_failure_aware_file",
                    lambda _path: False,
                )
                warm_result = scan_file(
                    str(metadata_path),
                    config={
                        "cache_enabled": True,
                        "cache_dir": str(cache_dir),
                        "min_cache_file_size": 0,
                    },
                )

            assert warm_result.success is True
            cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
            assert cached_entries > 0

            def fail_read(*_args: object, **_kwargs: object) -> object:
                raise OSError("simulated metadata read failure after cache warm")

            monkeypatch.setattr(metadata_scanner, "open", fail_read, raising=False)

            aggregate = scan_model_directory_or_file(
                str(metadata_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )

            assert aggregate.success is False
            assert aggregate.file_metadata[str(metadata_path)]["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
            assert aggregate.file_metadata[str(metadata_path)]["operational_error_reason"] == "metadata_read_failed"
            assert not any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
            )
            assert determine_exit_code(aggregate) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries

    def test_malformed_link_in_benign_readme(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text("IPv6 template: http://[host]/model\n", encoding="utf-8")

        result = MetadataScanner().scan(str(readme))

        assert result.success is True
        assert result.issues == []

    def test_scan_exposed_secrets_in_readme(self):
        """Test detection of exposed secrets in README."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                # Use a 48-character key after sk- to match the OpenAI API key pattern
                f.write(
                    "# Model Setup\n\n"
                    + "API Key: sk-1234567890abcdef1234567890abcdef1234567890abcdef\n"
                    + "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
                )

            result = scanner.scan(str(readme_path))

        assert len(result.issues) >= 1  # Should detect at least one potential secret
        assert any(issue.severity == IssueSeverity.INFO for issue in result.issues)

    def test_scan_exposed_secrets_preserves_classification_and_raw_aggregate_evidence(self, tmp_path: Path) -> None:
        """Keep metadata classification and raw aggregate secret evidence."""
        aws_key = "AKIAABCDEFGHIJKLMNOP"
        openai_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        bearer_token = "Bearer AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        readme_path = tmp_path / "README.md"
        readme_path.write_text(
            "\n".join(
                [
                    f"AWS key: {aws_key}",
                    f"OpenAI key: {openai_key}",
                    f"Auth header: {bearer_token}",
                ]
            ),
            encoding="utf-8",
        )

        direct = MetadataScanner().scan(str(readme_path))
        aggregate = scan_model_directory_or_file(str(readme_path), cache_scan_results=False)
        sarif_output = format_sarif_output(aggregate, [str(readme_path)])

        exposed_secret_issues = [
            issue for issue in direct.issues if issue.message.startswith("Potential exposed secret in text metadata")
        ]
        assert len(exposed_secret_issues) >= 3
        assert all(issue.details["match_preview"] == "<redacted>" for issue in exposed_secret_issues)

        direct_details = json.dumps([issue.details for issue in direct.issues], sort_keys=True)
        for secret in (aws_key, openai_key, bearer_token):
            assert secret not in direct_details

        for serialized in (aggregate.model_dump_json(), sarif_output):
            assert aws_key in serialized
            assert openai_key in serialized
            assert bearer_token in serialized

    def test_scan_ignores_placeholder_secrets(self) -> None:
        """Test that obvious placeholders are not flagged as secrets."""
        # Should not flag placeholders
        _assert_metadata_near_match_clean(
            "# Setup\n\nAPI Key: your_api_key_here\nToken: placeholder_token\nSecret: XXXXXXXXXX\n"
        )

    def test_scan_nonexistent_file(self):
        """Test handling of nonexistent files."""
        scanner = MetadataScanner()

        result = scanner.scan("/nonexistent/README.md")

        assert len(result.issues) >= 1
        # Base class _check_path returns CRITICAL for nonexistent paths
        assert result.issues[0].severity == IssueSeverity.CRITICAL
        assert "does not exist" in result.issues[0].message

    def test_bytes_scanned_reported(self) -> None:
        """Test that bytes scanned is properly reported."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Test README\n")

            expected_size = readme_path.stat().st_size
            result = scanner.scan(str(readme_path))

        assert result.bytes_scanned > 0
        assert result.bytes_scanned == expected_size

    def test_scan_enforces_size_limit(self, tmp_path: Path) -> None:
        """Metadata scans should stop when max_file_read_size is exceeded."""
        scanner = MetadataScanner(config={"max_file_read_size": 8})
        readme_path = tmp_path / "README.md"
        readme_path.write_text("# Test README\n")

        result = scanner.scan(str(readme_path))

        assert result.success is False
        size_checks = [check for check in result.checks if check.name == "File Size Limit"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.FAILED
        assert result.metadata["file_size"] == readme_path.stat().st_size

    def test_scan_enforces_timeout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Helper timeouts should report timeout only, not generic file errors."""
        scanner = MetadataScanner(config={"timeout": 1})
        readme_path = tmp_path / "README.md"
        readme_path.write_text("# Test README\n")

        def expire_timeout(_content: str, _file_path: str, _result: object) -> None:
            raise TimeoutError("metadata helper timed out")

        monkeypatch.setattr(scanner, "_check_exposed_secrets_in_text", expire_timeout)

        result = scanner.scan(str(readme_path))

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "scan_timeout"
        timeout_checks = [check for check in result.checks if check.name == "Metadata Scan Timeout"]
        assert len(timeout_checks) == 1
        assert timeout_checks[0].status == CheckStatus.FAILED
        assert timeout_checks[0].severity == IssueSeverity.INFO
        assert not any(check.name == "Metadata Scan Error" for check in result.checks)
        assert not any(issue.type == "file_error" for issue in result.issues)

    def test_scan_preserves_findings_when_timeout_fires_after_helper_return(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Findings emitted before the final timeout check should remain in the result."""
        scanner = MetadataScanner(config={"timeout": 1})
        readme_path = tmp_path / "README.md"
        readme_path.write_text("Download: https://example.com/model?token=sample-credential\n")

        timeout_calls = 0

        def raise_after_helper(*_args: object, **_kwargs: object) -> bool:
            nonlocal timeout_calls
            timeout_calls += 1
            if timeout_calls == 4:
                raise TimeoutError("metadata scan timed out after helper")
            return False

        monkeypatch.setattr(scanner, "_check_timeout", raise_after_helper)
        monkeypatch.setattr(scanner, "_check_exposed_secrets_in_text", lambda _content, _file_path, _result: None)

        result = scanner.scan(str(readme_path))

        timeout_checks = [check for check in result.checks if check.name == "Metadata Scan Timeout"]
        suspicious_issues = [
            issue
            for issue in result.issues
            if issue.details.get("url") == "https://example.com/model?token=sample-credential"
        ]

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "scan_timeout"
        assert len(timeout_checks) == 1
        assert len(suspicious_issues) == 1
        assert not any(check.name == "Metadata Scan Error" for check in result.checks)

    def test_scan_preserves_findings_when_timeout_occurs_mid_helper(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Findings produced before a helper timeout should remain in the result."""
        scanner = MetadataScanner(config={"timeout": 1})
        readme_path = tmp_path / "README.md"
        readme_path.write_text(
            "Download: https://example.com/model?token=sample-credential\nEndpoint: https://example.net/endpoint?token=another-credential\n"
        )

        timeout_calls = 0

        def raise_mid_helper(*_args: object, **_kwargs: object) -> bool:
            nonlocal timeout_calls
            timeout_calls += 1
            if timeout_calls == 4:
                raise TimeoutError("metadata helper timed out mid-scan")
            return False

        monkeypatch.setattr(scanner, "_check_timeout", raise_mid_helper)
        monkeypatch.setattr(scanner, "_check_exposed_secrets_in_text", lambda _content, _file_path, _result: None)

        result = scanner.scan(str(readme_path))

        timeout_checks = [check for check in result.checks if check.name == "Metadata Scan Timeout"]
        detected_urls = {issue.details["url"] for issue in result.issues if "url" in issue.details}

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "scan_timeout"
        assert len(timeout_checks) == 1
        assert detected_urls == {"https://example.com/model?token=sample-credential"}
        assert not any(check.name == "Metadata Scan Error" for check in result.checks)


def _assert_metadata_near_match_clean(contents: str) -> None:
    scanner = MetadataScanner()

    with tempfile.TemporaryDirectory() as temp_dir:
        readme_path = Path(temp_dir) / "README.md"
        with open(readme_path, "w") as f:
            f.write(contents)

        result = scanner.scan(str(readme_path))

    assert len(result.issues) == 0


def test_metadata_checks_credentials_without_reporting_passive_links(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text(
        "[Paper](https://bit.ly/sample) https://[invalid research.example 8.8.8.8\n"
        "[Resource](https://example.com/?token=sample-credential)\n",
        encoding="utf-8",
    )
    result = MetadataScanner().scan(str(path))
    assert result.success
    assert [check.name for check in result.checks if check.status == CheckStatus.FAILED] == [
        "Metadata URL Credential Check"
    ]
