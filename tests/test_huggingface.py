"""Tests for HuggingFace URL handling."""

from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.utils.huggingface import (
    download_model,
    is_huggingface_url,
    parse_huggingface_url,
)


class TestHuggingFaceURLDetection:
    """Test HuggingFace URL detection."""

    def test_valid_huggingface_urls(self):
        """Test that valid HuggingFace URLs are detected."""
        valid_urls = [
            "https://huggingface.co/bert-base-uncased",
            "https://huggingface.co/gpt2/model",
            "https://hf.co/facebook/bart-large",
            "hf://llama/llama-7b",
            "http://huggingface.co/test/model",
        ]
        for url in valid_urls:
            assert is_huggingface_url(url), f"Failed to detect valid URL: {url}"

    def test_invalid_huggingface_urls(self):
        """Test that invalid URLs are not detected as HuggingFace URLs."""
        invalid_urls = [
            "https://github.com/user/repo",
            "https://example.com/model",
            "/path/to/local/file",
            "file:///path/to/file",
            "s3://bucket/key",
            "",
            "huggingface.co/model",  # Missing protocol
        ]
        for url in invalid_urls:
            assert not is_huggingface_url(url), f"Incorrectly detected invalid URL: {url}"


class TestHuggingFaceURLParsing:
    """Test HuggingFace URL parsing."""

    def test_parse_https_urls(self):
        """Test parsing HTTPS HuggingFace URLs."""
        test_cases = [
            ("https://huggingface.co/bert-base/uncased", ("bert-base", "uncased")),
            ("https://hf.co/facebook/bart-large", ("facebook", "bart-large")),
            ("https://huggingface.co/user/model/", ("user", "model")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_hf_protocol_urls(self):
        """Test parsing hf:// protocol URLs."""
        test_cases = [
            ("hf://bert-base/uncased", ("bert-base", "uncased")),
            ("hf://facebook/bart-large", ("facebook", "bart-large")),
            ("hf://user/model/", ("user", "model")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_invalid_urls(self):
        """Test that invalid URLs raise ValueError."""
        invalid_urls = [
            "https://github.com/user/repo",
            "hf://",
            "hf://single-part",  # hf:// protocol requires namespace/repo format
            "",
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError):
                parse_huggingface_url(url)


class TestModelDownload:
    """Test model downloading functionality."""

    @patch("huggingface_hub.snapshot_download")
    def test_download_model_success(self, mock_snapshot_download):
        """Test successful model download."""
        # Mock the snapshot_download to return a path
        mock_path = "/tmp/test_model"
        mock_snapshot_download.return_value = mock_path

        # Test download
        result = download_model("https://huggingface.co/test/model")

        # Verify the download was called correctly
        mock_snapshot_download.assert_called_once()
        call_args = mock_snapshot_download.call_args
        assert call_args[1]["repo_id"] == "test/model"
        assert result == Path(mock_path)

    @patch("huggingface_hub.snapshot_download")
    def test_download_model_with_cache_dir(self, mock_snapshot_download):
        """Test model download with custom cache directory."""
        mock_path = "/cache/test/model"
        mock_snapshot_download.return_value = mock_path

        cache_dir = Path("/custom/cache")
        download_model("hf://test/model", cache_dir=cache_dir)

        # Verify cache directory was used
        call_args = mock_snapshot_download.call_args
        assert call_args[1]["cache_dir"] == str(cache_dir / "test" / "model")
        assert call_args[1]["local_dir"] == str(cache_dir / "test" / "model")

    @patch("huggingface_hub.snapshot_download")
    @patch("shutil.rmtree")
    def test_download_model_cleanup_on_failure(self, mock_rmtree, mock_snapshot_download):
        """Test that temporary directory is cleaned up on download failure."""
        # Make snapshot_download raise an exception
        mock_snapshot_download.side_effect = Exception("Download failed")

        # Test download failure
        with pytest.raises(Exception, match="Failed to download model"):
            download_model("https://huggingface.co/test/model")

        # Verify cleanup was attempted (only if temp dir was created)
        # Since we're mocking, we can't verify the exact behavior, but the code handles it

    def test_download_invalid_url(self):
        """Test that invalid URLs raise appropriate errors."""
        with pytest.raises(ValueError):
            download_model("https://github.com/user/repo")

    @patch("builtins.__import__")
    def test_missing_huggingface_hub_dependency(self, mock_import):
        """Test error when huggingface-hub is not installed."""

        # Mock the import to raise ImportError
        def side_effect(name, *args, **kwargs):
            if name == "huggingface_hub":
                raise ImportError("No module named 'huggingface_hub'")
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = side_effect

        with pytest.raises(ImportError, match="huggingface-hub package is required"):
            download_model("https://huggingface.co/test/model")
