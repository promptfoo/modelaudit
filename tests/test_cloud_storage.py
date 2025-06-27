from unittest.mock import MagicMock, patch

import pytest

from modelaudit.utils.cloud_storage import (
    download_from_cloud,
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

    url = "s3://bucket/model.pt"
    result = download_from_cloud(url, cache_dir=tmp_path)

    fs.get.assert_called_once_with(url, str(tmp_path), recursive=True)
    assert result == tmp_path


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
