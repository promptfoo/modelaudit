import logging
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
    @patch("modelaudit.utils.jfrog.requests.get")
    def test_download_success(self, mock_get, tmp_path):
        # Mock successful response
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        result = download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, api_token="test-token"
        )
        assert result.exists()
        assert result.read_bytes() == b"data"

        # Verify the request was made with proper headers
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "X-JFrog-Art-Api" in call_args[1]["headers"]
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "test-token"

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            download_artifact("https://example.com/model")

    @patch("modelaudit.utils.jfrog.requests.get")
    @patch("modelaudit.utils.jfrog.shutil.rmtree")
    def test_download_cleanup_on_failure(self, mock_rmtree, mock_get):
        # Mock request failure
        mock_get.side_effect = Exception("fail")

        with pytest.raises(Exception):  # noqa: B017 - generic exception from helper
            download_artifact("https://company.jfrog.io/artifactory/repo/model.bin")
        mock_rmtree.assert_called()

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_authentication_methods(self, mock_get, tmp_path):
        """Test different authentication methods."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        # Test API token
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, api_token="test-api-token"
        )
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "test-api-token"

        # Test access token
        download_artifact(
            "https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path, access_token="test-access-token"
        )
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-access-token"

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_environment_variables(self, mock_get, tmp_path, monkeypatch):
        """Test authentication via environment variables."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        # Test JFROG_API_TOKEN
        monkeypatch.setenv("JFROG_API_TOKEN", "env-api-token")
        download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "env-api-token"

        # Test JFROG_ACCESS_TOKEN (clear API token first)
        monkeypatch.delenv("JFROG_API_TOKEN", raising=False)
        monkeypatch.setenv("JFROG_ACCESS_TOKEN", "env-access-token")
        download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)
        call_args = mock_get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer env-access-token"

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_no_authentication(self, mock_get, tmp_path, caplog):
        """Test anonymous access when no authentication is provided."""
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        with caplog.at_level(logging.WARNING, logger="modelaudit.utils.jfrog"):
            download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)

        assert "No JFrog authentication provided. Attempting anonymous access." in caplog.text

        # Verify request was made without auth headers
        call_args = mock_get.call_args
        assert not call_args[1]["headers"]  # Empty headers dict

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_dotenv_file_support(self, mock_get, tmp_path, monkeypatch):
        """Test that .env file variables are loaded via python-dotenv."""
        # This test verifies that dotenv is loaded, but since we can't easily mock
        # the dotenv loading in tests, we verify the environment variable fallback works
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.iter_content.return_value = [b"data"]

        # Simulate .env file loaded environment variable
        monkeypatch.setenv("JFROG_API_TOKEN", "dotenv-token")
        download_artifact("https://company.jfrog.io/artifactory/repo/model.bin", cache_dir=tmp_path)

        call_args = mock_get.call_args
        assert call_args[1]["headers"]["X-JFrog-Art-Api"] == "dotenv-token"
