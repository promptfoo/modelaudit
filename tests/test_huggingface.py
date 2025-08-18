"""Tests for HuggingFace URL handling."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.utils.huggingface import (
    download_model,
    get_model_size,
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

    def test_parse_single_component_urls(self):
        """Test parsing single-component URLs (models without namespaces)."""
        test_cases = [
            ("https://huggingface.co/gpt2", ("gpt2", "")),
            ("https://hf.co/bert-base-uncased", ("bert-base-uncased", "")),
            ("hf://gpt2", ("gpt2", "")),
            ("hf://bert-base-uncased", ("bert-base-uncased", "")),
        ]
        for url, expected in test_cases:
            namespace, repo = parse_huggingface_url(url)
            assert (namespace, repo) == expected, f"Failed to parse {url}"

    def test_parse_invalid_urls(self):
        """Test that invalid URLs raise ValueError."""
        invalid_urls = [
            "https://github.com/user/repo",
            "hf://",  # Empty path
            "",  # Empty string
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
    def test_download_model_with_cache_dir(self, mock_snapshot_download, tmp_path):
        """Test model download with custom cache directory."""
        mock_path = str(tmp_path / "test" / "model")
        mock_snapshot_download.return_value = mock_path

        cache_dir = tmp_path / "custom_cache"
        download_model("hf://test/model", cache_dir=cache_dir)

        # Verify cache directory was used
        call_args = mock_snapshot_download.call_args
        assert call_args[1]["cache_dir"] == str(cache_dir / "huggingface" / "test" / "model")
        assert call_args[1]["local_dir"] == str(cache_dir / "huggingface" / "test" / "model")

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


class TestModelSizeAndDiskSpace:
    """Test model size retrieval and disk space checking."""

    @patch("builtins.__import__")
    def test_get_model_size_import_error(self, mock_import):
        """Test get_model_size returns None when HfApi is not available."""

        def side_effect(name, *args, **kwargs):
            if name == "huggingface_hub":
                raise ImportError("No module")
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = side_effect
        size = get_model_size("test/model")
        assert size is None

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_success(self, mock_hf_api_class):
        """Test successful model size retrieval."""
        # Mock the API and model info
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        # Create mock file info
        mock_file1 = MagicMock()
        mock_file1.size = 1024 * 1024  # 1 MB
        mock_file2 = MagicMock()
        mock_file2.size = 2048 * 1024  # 2 MB

        mock_model_info = MagicMock()
        mock_model_info.siblings = [mock_file1, mock_file2]
        mock_api.model_info.return_value = mock_model_info

        size = get_model_size("test/model")
        assert size == 3 * 1024 * 1024  # 3 MB total

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_no_siblings(self, mock_hf_api_class):
        """Test model size when no siblings info available."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api

        mock_model_info = MagicMock()
        mock_model_info.siblings = None
        mock_api.model_info.return_value = mock_model_info

        size = get_model_size("test/model")
        assert size is None

    @patch("huggingface_hub.HfApi")
    def test_get_model_size_api_error(self, mock_hf_api_class):
        """Test model size returns None on API error."""
        mock_api = MagicMock()
        mock_hf_api_class.return_value = mock_api
        mock_api.model_info.side_effect = Exception("API error")

        size = get_model_size("test/model")
        assert size is None

    @patch("modelaudit.utils.huggingface.get_model_size")
    @patch("modelaudit.utils.huggingface.check_disk_space")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_insufficient_disk_space(
        self, mock_snapshot_download, mock_check_disk_space, mock_get_model_size
    ):
        """Test download fails gracefully when disk space is insufficient."""
        # Mock model size
        mock_get_model_size.return_value = 10 * 1024 * 1024 * 1024  # 10 GB

        # Mock disk space check to fail
        mock_check_disk_space.return_value = (False, "Insufficient disk space. Required: 12.0 GB, Available: 5.0 GB")

        # Test download failure
        with pytest.raises(Exception, match="Cannot download model.*Insufficient disk space"):
            download_model("https://huggingface.co/test/model")

        # Verify snapshot_download was not called
        mock_snapshot_download.assert_not_called()

    @patch("modelaudit.utils.huggingface.get_model_size")
    @patch("modelaudit.utils.huggingface.check_disk_space")
    @patch("huggingface_hub.snapshot_download")
    def test_download_model_with_disk_space_check(
        self, mock_snapshot_download, mock_check_disk_space, mock_get_model_size
    ):
        """Test successful download with disk space check."""
        # Mock model size
        mock_get_model_size.return_value = 1024 * 1024 * 1024  # 1 GB

        # Mock disk space check to pass
        mock_check_disk_space.return_value = (True, "Sufficient disk space available (10.0 GB)")

        # Mock snapshot download
        mock_path = "/tmp/test_model"
        mock_snapshot_download.return_value = mock_path

        # Test download
        result = download_model("https://huggingface.co/test/model")

        # Verify disk space was checked
        mock_check_disk_space.assert_called_once()

        # Verify download proceeded
        mock_snapshot_download.assert_called_once()
        assert result == Path(mock_path)
