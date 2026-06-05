"""Tests for metadata scanner."""

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import ParseResult

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.integrations.sarif_formatter import format_sarif_output
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners import metadata_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.metadata_scanner import MetadataScanner
from modelaudit.utils.helpers import cache_decorator


class TestMetadataScanner:
    """Test metadata scanner functionality."""

    def test_known_secret_format_reuses_lowered_description(self) -> None:
        class CountingDescription(str):
            lower_calls = 0

            def lower(self) -> str:
                self.lower_calls += 1
                return super().lower()

        description = CountingDescription("OpenAI API Key")

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
        """Unreadable routed metadata should fail closed without a fabricated security issue."""
        readme_path = tmp_path / "README"
        readme_path.write_text("# Model Card\n\nThis README is benign.\n")
        cache_dir = tmp_path / "cache"

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

        reset_cache_manager()
        try:
            aggregates = [
                scan_model_directory_or_file(
                    str(readme_path),
                    cache_enabled=True,
                    cache_dir=str(cache_dir),
                    min_cache_file_size=0,
                )
                for _ in range(2)
            ]

            for aggregate in aggregates:
                assert aggregate.success is False
                assert not any(
                    issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
                )
                assert determine_exit_code(aggregate) == 2
            assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
        finally:
            reset_cache_manager()

    def test_metadata_invalid_utf8_is_operational_not_security_finding(self, tmp_path: Path) -> None:
        readme_path = tmp_path / "README"
        readme_path.write_bytes(b"# Model Card\n\ninvalid text: \xff\n")

        direct = MetadataScanner().scan(str(readme_path))
        aggregate = scan_model_directory_or_file(str(readme_path), cache_scan_results=False)

        assert direct.success is False
        assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
        assert direct.metadata["operational_error_reason"] == "metadata_read_failed"
        read_check = next(check for check in direct.checks if check.name == "Metadata File Read")
        assert read_check.details["exception_type"] == "UnicodeDecodeError"
        assert read_check.severity == IssueSeverity.INFO
        assert read_check.rule_code is None
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert determine_exit_code(aggregate) == 2

    def test_metadata_permission_failure_is_operational_after_preflight(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        readme_path = tmp_path / "README"
        readme_path.write_text("# Model Card\n", encoding="utf-8")
        real_access = os.access

        def inaccessible_owned_path(path: str, mode: int) -> bool:
            return False if path == str(readme_path) else real_access(path, mode)

        monkeypatch.setattr("modelaudit.scanners.base.os.access", inaccessible_owned_path)

        direct = MetadataScanner().scan(str(readme_path))
        aggregate = scan_model_directory_or_file(str(readme_path), cache_scan_results=False)

        assert direct.success is False
        assert direct.metadata["operational_error_reason"] == "metadata_read_failed"
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in direct.issues)
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert determine_exit_code(aggregate) == 2

    def test_metadata_read_failure_bypasses_stale_clean_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        metadata_path = tmp_path / "model-index.yml"
        metadata_path.write_text("model-index:\n- name: clean-model\n" + "x" * 11_000, encoding="utf-8")
        cache_dir = tmp_path / "cache"

        reset_cache_manager()
        try:
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
        finally:
            reset_cache_manager()

    def test_scan_suspicious_urls_in_readme(self) -> None:
        """Test detection of suspicious URLs in README."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write(
                    "# Model Info\n\n"
                    "- Download: https://bit.ly/suspicious-model\n"
                    "- Endpoint: https://ngrok.io/malicious-endpoint\n"
                )

            result = scanner.scan(str(readme_path))

        assert len(result.issues) == 2
        assert all(issue.severity == IssueSeverity.INFO for issue in result.issues)
        assert {issue.details.get("suspicious_domain") for issue in result.issues} == {
            "bit.ly",
            "ngrok.io",
        }

    def test_repeated_benign_urls_are_parsed_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Skip duplicate benign URLs before reparsing them."""
        scanner = MetadataScanner()
        result = scanner._create_result()
        parse_calls = 0
        real_urlparse = metadata_scanner.urlparse

        def tracking_urlparse(url: str) -> ParseResult:
            nonlocal parse_calls
            parse_calls += 1
            return real_urlparse(url)

        monkeypatch.setattr(metadata_scanner, "urlparse", tracking_urlparse)

        scanner._check_suspicious_urls_in_text(
            "\n".join(["https://huggingface.co/example/model"] * 3),
            "README.md",
            result,
        )

        assert parse_calls == 1
        assert result.issues == []

    def test_scan_detects_suspicious_subdomain_hosts(self) -> None:
        """Test suspicious domains are detected through subdomain matching."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Model Info\n\n- Endpoint: https://api.ngrok.io/malicious-endpoint\n")

            result = scanner.scan(str(readme_path))

        assert len(result.issues) == 1
        issue = result.issues[0]
        assert issue.severity == IssueSeverity.INFO
        assert issue.details.get("suspicious_domain") == "ngrok.io"
        assert "https://api.ngrok.io/malicious-endpoint" in str(issue.details.get("url"))

    def test_scan_ignores_suspicious_domain_substrings(self) -> None:
        """Test URLs are matched by hostname, not generic substring."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write(
                    "# Model Info\n\n"
                    "- Docs: https://example.com/guide?redirect=bit.ly/suspicious-model\n"
                    "- API: https://safe-ngrok.io/docs\n"
                )

            result = scanner.scan(str(readme_path))

        assert len(result.issues) == 0

    def test_scan_detects_suspicious_domains_hidden_in_userinfo(self, tmp_path: Path) -> None:
        """Shorteners and tunnel domains in userinfo should still be flagged."""
        scanner = MetadataScanner()
        readme_path = tmp_path / "README.md"
        readme_path.write_text(
            "# Model Info\n\n"
            "- Shortener bait: https://bit.ly@github.com/download\n"
            "- Password bait: https://user:bit.ly@github.com/download-two\n"
            "- Encoded bait: https://%62it.ly@github.com/download-three\n"
            "- Tunnel bait: https://localtunnel.me:token@huggingface.co/proxy\n"
            "- Docs: https://example.com/model-card\n"
        )

        result = scanner.scan(str(readme_path))

        assert len(result.issues) == 4
        flagged = {
            (issue.details.get("suspicious_domain"), issue.details.get("url_component")) for issue in result.issues
        }
        assert flagged == {("bit.ly", "userinfo"), ("localtunnel.me", "userinfo")}
        flagged_urls = {issue.details.get("url") for issue in result.issues}
        assert "https://github.com/download" in flagged_urls
        assert "https://github.com/download-two" in flagged_urls
        assert "https://github.com/download-three" in flagged_urls
        assert "https://huggingface.co/proxy" in flagged_urls
        assert "https://example.com/model-card" not in flagged_urls

    def test_scan_suspicious_urls_redacts_credentials_and_query(self, tmp_path: Path) -> None:
        """Suspicious URL findings should not preserve credentials or signed query strings."""
        scanner = MetadataScanner()
        readme_path = tmp_path / "README.md"
        readme_path.write_text("Download: https://user:pass@tinyurl.com/model.bin?token=SECRET_TOKEN#SECRET_FRAGMENT\n")

        result = scanner.scan(str(readme_path))

        assert len(result.issues) == 1
        issue = result.issues[0]
        assert issue.details["url"] == "https://tinyurl.com/model.bin"
        assert "tinyurl.com/model.bin" in issue.message
        serialized = f"{issue.message} {issue.details['url']}"
        assert "user:pass" not in serialized
        assert "SECRET_TOKEN" not in serialized
        assert "SECRET_FRAGMENT" not in serialized

    def test_scan_suspicious_urls_redacts_path_tokens_in_outputs(self, tmp_path: Path) -> None:
        """Suspicious URL findings should not preserve credentials embedded in paths."""
        aws_key = "AKIAABCDEFGHIJKLMNOP"
        readme_path = tmp_path / "README.md"
        readme_path.write_text(
            f"Download: https://tinyurl.com/download/{aws_key}/model.bin?token=SECRET_TOKEN#SECRET_FRAGMENT\n",
            encoding="utf-8",
        )

        direct = MetadataScanner().scan(str(readme_path))
        aggregate = scan_model_directory_or_file(str(readme_path), cache_scan_results=False)
        sarif_output = format_sarif_output(aggregate, [str(readme_path)])

        suspicious_url_issue = next(
            issue for issue in direct.issues if issue.details.get("suspicious_domain") == "tinyurl.com"
        )
        assert suspicious_url_issue.details["url"] == "https://tinyurl.com/download/<redacted>/model.bin"
        assert "tinyurl.com/download/<redacted>/model.bin" in suspicious_url_issue.message

        serialized_outputs = [
            json.dumps([issue.model_dump() for issue in direct.issues], sort_keys=True),
            aggregate.model_dump_json(),
            sarif_output,
        ]
        for serialized in serialized_outputs:
            assert aws_key not in serialized
            assert "SECRET_TOKEN" not in serialized
            assert "SECRET_FRAGMENT" not in serialized

    def test_scan_ignores_non_suspicious_authenticated_url(self, tmp_path: Path) -> None:
        """Authenticated URLs without suspicious domains should stay quiet."""
        scanner = MetadataScanner()
        readme_path = tmp_path / "README.md"
        readme_path.write_text("Download: https://user:token@example.com/private-model\n")

        result = scanner.scan(str(readme_path))

        assert len(result.issues) == 0

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

    def test_scan_exposed_secrets_redacts_match_preview_in_outputs(self, tmp_path: Path) -> None:
        """Secret details should not preserve raw prefixes or token values."""
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

        serialized_outputs = [
            json.dumps([issue.details for issue in direct.issues], sort_keys=True),
            aggregate.model_dump_json(),
            sarif_output,
        ]
        for serialized in serialized_outputs:
            assert aws_key not in serialized
            assert openai_key not in serialized
            assert bearer_token not in serialized
            assert "AKIAABCDEFGHIJKLMNOP" not in serialized

    def test_scan_ignores_placeholder_secrets(self) -> None:
        """Test that obvious placeholders are not flagged as secrets."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Setup\n\nAPI Key: your_api_key_here\nToken: placeholder_token\nSecret: XXXXXXXXXX\n")

            result = scanner.scan(str(readme_path))

        # Should not flag placeholders
        assert len(result.issues) == 0

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

        monkeypatch.setattr(scanner, "_check_suspicious_urls_in_text", expire_timeout)

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
        readme_path.write_text("Download: https://bit.ly/suspicious-model\n")

        timeout_calls = 0

        def raise_after_helper(*_args: object, **_kwargs: object) -> bool:
            nonlocal timeout_calls
            timeout_calls += 1
            if timeout_calls == 5:
                raise TimeoutError("metadata scan timed out after helper")
            return False

        monkeypatch.setattr(scanner, "_check_timeout", raise_after_helper)
        monkeypatch.setattr(scanner, "_check_exposed_secrets_in_text", lambda _content, _file_path, _result: None)

        result = scanner.scan(str(readme_path))

        timeout_checks = [check for check in result.checks if check.name == "Metadata Scan Timeout"]
        suspicious_issues = [issue for issue in result.issues if issue.details.get("suspicious_domain") == "bit.ly"]

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
            "Download: https://bit.ly/suspicious-model\nEndpoint: https://ngrok.io/malicious-endpoint\n"
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
        detected_domains = {
            issue.details["suspicious_domain"] for issue in result.issues if "suspicious_domain" in issue.details
        }

        assert result.success is False
        assert result.metadata["operational_error_reason"] == "scan_timeout"
        assert len(timeout_checks) == 1
        assert detected_domains == {"bit.ly"}
        assert not any(check.name == "Metadata Scan Error" for check in result.checks)
