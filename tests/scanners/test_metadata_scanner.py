"""Tests for metadata scanner."""

import tempfile
from pathlib import Path

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.metadata_scanner import MetadataScanner


class TestMetadataScanner:
    """Test metadata scanner functionality."""

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

    def test_scan_valid_readme(self):
        """Test scanning valid README file."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# My Model\\n\\nThis is a clean README with no security issues.\\n")

            result = scanner.scan(str(readme_path))

        assert result.scanner_name == "metadata"
        assert len(result.issues) == 0  # Clean README should have no issues

    def test_scan_suspicious_urls_in_readme(self):
        """Test detection of suspicious URLs in README."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write(
                    "# Model Info\\n\\n- Download: https://bit.ly/suspicious-model\\n- Endpoint: https://ngrok.io/malicious-endpoint\\n"
                )

            result = scanner.scan(str(readme_path))

        assert len(result.issues) == 2
        assert all(issue.severity == IssueSeverity.INFO for issue in result.issues)
        assert {issue.details.get("suspicious_domain") for issue in result.issues} == {
            "bit.ly",
            "ngrok.io",
        }
        assert any("bit.ly" in issue.message for issue in result.issues)
        assert any("ngrok.io" in issue.message for issue in result.issues)

    def test_scan_detects_suspicious_subdomain_hosts(self):
        """Test suspicious domains are detected through subdomain matching."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Model Info\\n\\n- Endpoint: https://api.ngrok.io/malicious-endpoint\\n")

            result = scanner.scan(str(readme_path))

        assert len(result.issues) == 1
        issue = result.issues[0]
        assert issue.severity == IssueSeverity.INFO
        assert issue.details.get("suspicious_domain") == "ngrok.io"
        assert "https://api.ngrok.io/malicious-endpoint" in str(issue.details.get("url"))

    def test_scan_ignores_suspicious_domain_substrings(self):
        """Test URLs are matched by hostname, not generic substring."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write(
                    "# Model Info\\n\\n"
                    "- Docs: https://example.com/guide?redirect=bit.ly/suspicious-model\\n"
                    "- API: https://safe-ngrok.io/docs\\n"
                )

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

    def test_scan_ignores_placeholder_secrets(self):
        """Test that obvious placeholders are not flagged as secrets."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Setup\\n\\nAPI Key: your_api_key_here\\nToken: placeholder_token\\nSecret: XXXXXXXXXX\\n")

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

    def test_bytes_scanned_reported(self):
        """Test that bytes scanned is properly reported."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write("# Test README\\n")

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

        assert result.success is True
        timeout_checks = [check for check in result.checks if check.name == "Metadata Scan Timeout"]
        assert len(timeout_checks) == 1
        assert timeout_checks[0].status == CheckStatus.FAILED
        assert timeout_checks[0].severity == IssueSeverity.WARNING
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

        assert result.success is True
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

        assert result.success is True
        assert len(timeout_checks) == 1
        assert detected_domains == {"bit.ly"}
        assert not any(check.name == "Metadata Scan Error" for check in result.checks)
