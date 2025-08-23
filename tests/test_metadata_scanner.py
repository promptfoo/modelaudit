"""Tests for metadata scanner."""

import json
import tempfile
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.metadata_scanner import MetadataScanner


class TestMetadataScanner:
    """Test metadata scanner functionality."""

    def test_can_handle_json_configs(self):
        """Test that scanner handles JSON configuration files."""
        scanner = MetadataScanner()

        assert scanner.can_handle("config.json")
        assert scanner.can_handle("tokenizer_config.json")
        assert scanner.can_handle("generation_config.json")

    def test_can_handle_text_metadata(self):
        """Test that scanner handles text metadata files."""
        scanner = MetadataScanner()

        assert scanner.can_handle("README")
        assert scanner.can_handle("readme")
        assert scanner.can_handle("README.md")
        assert scanner.can_handle("readme.txt")
        assert scanner.can_handle("model_card.md")
        assert scanner.can_handle("model_card.txt")
        assert scanner.can_handle("model-index.yml")
        assert scanner.can_handle("model-index.yaml")

    def test_cannot_handle_other_files(self):
        """Test that scanner rejects non-metadata files."""
        scanner = MetadataScanner()

        assert not scanner.can_handle("model.pkl")
        assert not scanner.can_handle("pytorch_model.bin")
        assert not scanner.can_handle("data.txt")

    def test_scan_valid_json_config(self):
        """Test scanning valid JSON configuration."""
        scanner = MetadataScanner()
        config = {"model_type": "bert", "hidden_size": 768, "num_layers": 12}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert result.scanner_name == "metadata"
        assert len(result.issues) == 0  # Clean config should have no issues

        # Cleanup
        Path(f.name).unlink()

    def test_scan_suspicious_url_in_config(self):
        """Test detection of suspicious URLs in configuration."""
        scanner = MetadataScanner()
        config = {"model_url": "https://bit.ly/suspicious-model", "download_url": "https://ngrok.io/malicious-endpoint"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) == 2
        assert all(issue.severity == IssueSeverity.WARNING for issue in result.issues)
        assert any("bit.ly" in issue.message for issue in result.issues)
        assert any("ngrok.io" in issue.message for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_exposed_secrets_in_config(self):
        """Test detection of exposed secrets in configuration."""
        scanner = MetadataScanner()
        config = {
            "api_key": "sk-1234567890abcdef",
            "auth_token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "secret": "not_a_placeholder_value_123",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 1  # Should detect at least one real secret
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("api_key" in issue.message for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_ignores_placeholder_secrets(self):
        """Test that obvious placeholders are not flagged as secrets."""
        scanner = MetadataScanner()
        config = {"api_key": "your_api_key_here", "token": "placeholder_token", "secret": "XXXXXXXXXX"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        # Should not flag placeholders
        assert len(result.issues) == 0

        # Cleanup
        Path(f.name).unlink()

    def test_scan_auto_map_entries(self):
        """Test detection of dangerous auto_map entries."""
        scanner = MetadataScanner()
        config = {"auto_map": {"AutoModel": "custom_model.py", "AutoTokenizer": "os.system('rm -rf /')"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 1  # Should detect at least one dangerous reference
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
        assert any("os" in issue.message for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_custom_code_references(self):
        """Test detection of custom code references."""
        scanner = MetadataScanner()
        config = {"custom_objects": "import os; os.system('malicious')", "lambda_layer": "lambda x: eval(x)"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 2  # Should detect multiple dangerous patterns
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_text_metadata_with_urls(self):
        """Test scanning text metadata files for suspicious URLs."""
        scanner = MetadataScanner()
        content = """# Model Card

This model is available at: https://bit.ly/suspicious-link

For more info: https://ngrok.io/tunnel
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 2  # Should detect multiple suspicious URLs
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_text_metadata_with_secrets(self):
        """Test scanning text metadata for exposed secrets."""
        scanner = MetadataScanner()
        content = """# Setup Instructions

Set your API key: sk-1234567890abcdef1234567890abcdef12345678

GitHub token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write(content)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 1  # Should detect at least one potential secret
        assert any(issue.severity == IssueSeverity.WARNING for issue in result.issues)

        # Cleanup
        Path(f.name).unlink()

    def test_scan_invalid_json(self):
        """Test handling of invalid JSON files."""
        scanner = MetadataScanner()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"invalid": json}')  # Invalid JSON
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) == 1
        assert result.issues[0].severity == IssueSeverity.WARNING
        assert "Invalid JSON" in result.issues[0].message

        # Cleanup
        Path(f.name).unlink()

    def test_scan_nonexistent_file(self):
        """Test handling of nonexistent files."""
        scanner = MetadataScanner()

        result = scanner.scan("/nonexistent/file.json")

        assert len(result.issues) == 1
        assert result.issues[0].severity == IssueSeverity.WARNING
        assert "Error reading" in result.issues[0].message

    def test_scan_nested_config_structure(self):
        """Test scanning nested configuration structures."""
        scanner = MetadataScanner()
        config = {
            "model": {"endpoints": {"inference": "https://tinyurl.com/malicious"}},
            "auth": {"credentials": {"api_key": "real_key_12345"}},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert len(result.issues) >= 2  # Should detect multiple issues
        # Should detect both suspicious URL and potential secret
        severities = {issue.severity for issue in result.issues}
        assert IssueSeverity.WARNING in severities
        assert IssueSeverity.CRITICAL in severities

        # Cleanup
        Path(f.name).unlink()

    def test_bytes_scanned_reported(self):
        """Test that bytes scanned is properly reported."""
        scanner = MetadataScanner()
        config = {"model_type": "test"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()

            result = scanner.scan(f.name)

        assert result.bytes_scanned > 0
        assert result.bytes_scanned == Path(f.name).stat().st_size

        # Cleanup
        Path(f.name).unlink()
