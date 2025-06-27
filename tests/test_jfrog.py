from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.utils.jfrog import download_artifact, is_jfrog_url


class TestJFrogURLDetection:
    def test_valid_jfrog_urls(self):
        valid_urls = [
            "https://company.jfrog.io/artifactory/repo/model.bin",
            "http://my-jfrog.com/artifactory/libs-release/model.pt",
        ]
        for url in valid_urls:
            assert is_jfrog_url(url)

    def test_invalid_jfrog_urls(self):
        invalid_urls = [
            "https://example.com/model",
            "hf://model",
            "",
        ]
        for url in invalid_urls:
            assert not is_jfrog_url(url)


class TestJFrogDownload:
    @patch("modelaudit.utils.jfrog.urlretrieve")
    def test_download_success(self, mock_retrieve, tmp_path):
        def fake_retrieve(url, path):
            Path(path).write_text("data")

        mock_retrieve.side_effect = fake_retrieve
        result = download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)
        assert result.exists()
        assert result.read_text() == "data"

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            download_artifact("https://example.com/model")

    @patch("modelaudit.utils.jfrog.urlretrieve")
    @patch("modelaudit.utils.jfrog.shutil.rmtree")
    def test_download_cleanup_on_failure(self, mock_rmtree, mock_retrieve):
        mock_retrieve.side_effect = Exception("fail")
        with pytest.raises(Exception):  # noqa: B017 - generic exception from helper
            download_artifact("https://company.jfrog.io/artifactory/repo/model.bin")
        mock_rmtree.assert_called()
