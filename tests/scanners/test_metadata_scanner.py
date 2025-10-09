"""Tests for metadata scanner."""

import tempfile
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
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
        assert all(issue.severity == IssueSeverity.WARNING for issue in result.issues)
        assert any("bit.ly" in issue.message for issue in result.issues)
        assert any("ngrok.io" in issue.message for issue in result.issues)

    def test_scan_exposed_secrets_in_readme(self):
        """Test detection of exposed secrets in README."""
        scanner = MetadataScanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            readme_path = Path(temp_dir) / "README.md"
            with open(readme_path, "w") as f:
                f.write(
                    "# Model Setup\\n\\n"
                    + "API Key: sk-1234567890abcdef1234567890abcdef12345678\\n"
                    + "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n"
                )

            result = scanner.scan(str(readme_path))

        assert len(result.issues) >= 1  # Should detect at least one potential secret
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)

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

        assert len(result.issues) == 1
        assert result.issues[0].severity == IssueSeverity.WARNING
        assert "Error reading" in result.issues[0].message

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
