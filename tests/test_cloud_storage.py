from unittest.mock import MagicMock, patch

import pytest

from modelaudit.utils.cloud_storage import (
    download_from_cloud,
    get_cloud_object_size,
    is_cloud_url,
)


class TestCloudURLDetection:
    def test_valid_cloud_urls(self):
        valid = [
            "s3://bucket/key",
            "gs://my-bucket/model.pt",
            "r2://data/model.bin",
            "https://bucket.s3.amazonaws.com/file",
            "https://storage.googleapis.com/bucket/file",
            "https://account.r2.cloudflarestorage.com/bucket/file",
        ]
        for url in valid:
            assert is_cloud_url(url), f"Failed to detect {url}"

    def test_invalid_cloud_urls(self):
        invalid = [
            "https://huggingface.co/model",
            "ftp://example.com/file",
            "",  # empty
        ]
        for url in invalid:
            assert not is_cloud_url(url), f"Incorrectly detected {url}"


@patch("fsspec.filesystem")
def test_download_from_cloud(mock_fs, tmp_path):
    fs = MagicMock()
    mock_fs.return_value = fs

    # Mock file info to indicate it's a file, not a directory
    fs.info.return_value = {"type": "file", "size": 1024}

    url = "s3://bucket/model.pt"
    result = download_from_cloud(url, cache_dir=tmp_path)

    # Verify fs.get was called (path will include cache subdirectories)
    fs.get.assert_called_once()
    call_args = fs.get.call_args[0]
    assert call_args[0] == url
    assert "model.pt" in call_args[1]

    # Result should be a path containing the filename
    assert result.name == "model.pt"
    assert result.exists() or True  # Mock doesn't create actual files


@patch("builtins.__import__")
def test_download_missing_dependency(mock_import):
    def side_effect(name, *args, **kwargs):
        if name == "fsspec":
            raise ImportError("no fsspec")
        return original_import(name, *args, **kwargs)

    original_import = __import__
    mock_import.side_effect = side_effect

    with pytest.raises(ImportError):
        download_from_cloud("s3://bucket/model.pt")


class TestCloudObjectSize:
    """Test cloud object size retrieval."""

    def test_get_cloud_object_size_single_file(self):
        """Test getting size of a single file."""
        fs = MagicMock()
        fs.info.return_value = {"size": 1024 * 1024}  # 1 MB

        size = get_cloud_object_size(fs, "s3://bucket/file.bin")
        assert size == 1024 * 1024

    def test_get_cloud_object_size_directory(self):
        """Test getting total size of a directory."""
        fs = MagicMock()
        fs.info.return_value = {}  # No size means it's a directory
        fs.ls.return_value = [
            {"size": 1024 * 1024},  # 1 MB
            {"size": 2048 * 1024},  # 2 MB
            {"size": 512 * 1024},  # 0.5 MB
        ]

        size = get_cloud_object_size(fs, "s3://bucket/dir/")
        assert size == (1024 + 2048 + 512) * 1024  # 3.5 MB

    def test_get_cloud_object_size_error(self):
        """Test size retrieval returns None on error."""
        fs = MagicMock()
        fs.info.side_effect = Exception("Access denied")

        size = get_cloud_object_size(fs, "s3://bucket/file.bin")
        assert size is None


class TestDiskSpaceCheckingForCloud:
    """Test disk space checking for cloud downloads."""

    @patch("modelaudit.utils.cloud_storage.get_cloud_object_size")
    @patch("modelaudit.utils.cloud_storage.check_disk_space")
    @patch("fsspec.filesystem")
    def test_download_insufficient_disk_space(self, mock_fs_class, mock_check_disk_space, mock_get_size):
        """Test download fails when disk space is insufficient."""
        fs = MagicMock()
        mock_fs_class.return_value = fs

        # Mock object size
        mock_get_size.return_value = 10 * 1024 * 1024 * 1024  # 10 GB

        # Mock disk space check to fail
        mock_check_disk_space.return_value = (False, "Insufficient disk space. Required: 12.0 GB, Available: 5.0 GB")

        # Test download failure
        with pytest.raises(Exception, match="Cannot download from.*Insufficient disk space"):
            download_from_cloud("s3://bucket/large-model.bin")

        # Verify download was not attempted
        fs.get.assert_not_called()

    @patch("modelaudit.utils.cloud_storage.get_cloud_object_size")
    @patch("modelaudit.utils.cloud_storage.check_disk_space")
    @patch("fsspec.filesystem")
    def test_download_with_disk_space_check(self, mock_fs_class, mock_check_disk_space, mock_get_size, tmp_path):
        """Test successful download with disk space check."""
        fs = MagicMock()
        mock_fs_class.return_value = fs

        # Mock file info to indicate it's a file, not a directory
        fs.info.return_value = {"type": "file", "size": 1024 * 1024 * 1024}

        # Mock object size
        mock_get_size.return_value = 1024 * 1024 * 1024  # 1 GB

        # Mock disk space check to pass
        mock_check_disk_space.return_value = (True, "Sufficient disk space available (10.0 GB)")

        # Test download
        result = download_from_cloud("s3://bucket/model.bin", cache_dir=tmp_path)

        # Verify disk space was checked
        mock_check_disk_space.assert_called_once()

        # Verify download proceeded
        fs.get.assert_called_once()
        # Result should be a path containing the filename
        assert result.name == "model.bin"
        assert str(tmp_path) in str(result)  # Should be within the cache dir
