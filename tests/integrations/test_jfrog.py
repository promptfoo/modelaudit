import logging
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from modelaudit.utils.sources.jfrog import (
    detect_jfrog_target_type,
    download_artifact,
    download_jfrog_folder,
    filter_scannable_files,
    format_size,
    get_storage_api_url,
    is_jfrog_url,
    list_jfrog_folder_contents,
)


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


class TestJFrogStorageAPI:
    """Test Storage API URL conversion and folder operations."""

    def test_get_storage_api_url(self):
        """Test conversion of artifact URLs to Storage API URLs."""
        test_cases = [
            (
                "https://company.jfrog.io/artifactory/repo/model.pkl",
                "https://company.jfrog.io/artifactory/api/storage/repo/model.pkl",
            ),
            (
                "https://my-jfrog.com/artifactory/libs-release/models/",
                "https://my-jfrog.com/artifactory/api/storage/libs-release/models/",
            ),
            (
                "http://localhost:8081/artifactory/local-repo/path/to/file.bin",
                "http://localhost:8081/artifactory/api/storage/local-repo/path/to/file.bin",
            ),
        ]

        for artifact_url, expected_storage_url in test_cases:
            result = get_storage_api_url(artifact_url)
            assert result == expected_storage_url

    def test_get_storage_api_url_invalid(self):
        """Test error handling for invalid URLs."""
        invalid_urls = [
            "https://example.com/file.pkl",  # No artifactory in path
            "not-a-url",  # Invalid URL format
        ]

        for url in invalid_urls:
            with pytest.raises(ValueError):
                get_storage_api_url(url)

    def test_format_size(self):
        """Test human-readable size formatting."""
        test_cases = [
            (0, "0.0 B"),
            (512, "512.0 B"),
            (1024, "1.0 KB"),
            (1536, "1.5 KB"),
            (1048576, "1.0 MB"),
            (1073741824, "1.0 GB"),
        ]

        for size_bytes, expected in test_cases:
            result = format_size(size_bytes)
            assert result == expected

    def test_filter_scannable_files(self):
        """Test filtering of files to scannable model types."""
        files = [
            {"name": "model.pkl", "path": "/repo/model.pkl", "size": 1024},
            {"name": "data.txt", "path": "/repo/data.txt", "size": 512},
            {"name": "model.pt", "path": "/repo/model.pt", "size": 2048},
            {"name": "config.json", "path": "/repo/config.json", "size": 256},
            {"name": "weights.safetensors", "path": "/repo/weights.safetensors", "size": 4096},
        ]

        scannable = filter_scannable_files(files)

        assert len(scannable) == 3
        scannable_names = {f["name"] for f in scannable}
        assert scannable_names == {"model.pkl", "model.pt", "weights.safetensors"}


class TestJFrogFolderDetection:
    """Test JFrog folder detection and listing."""

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_detect_jfrog_target_type_file(self, mock_get, tmp_path):
        """Test detection of JFrog file targets."""
        # Mock response for a file
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "repo": "my-repo",
            "path": "/model.pkl",
            "size": 1024,
            "lastModified": "2024-01-01T00:00:00.000Z",
        }

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl", api_token="test-token")

        assert result["type"] == "file"
        assert result["size"] == 1024
        assert result["repo"] == "my-repo"

        # Verify Storage API URL was called
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert "api/storage" in called_url

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_detect_jfrog_target_type_folder(self, mock_get):
        """Test detection of JFrog folder targets."""
        # Mock response for a folder with children
        mock_response = mock_get.return_value
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "repo": "my-repo",
            "path": "/models",
            "children": [
                {"uri": "/model1.pkl", "folder": False, "size": 1024},
                {"uri": "/subfolder", "folder": True},
                {"uri": "/model2.pt", "folder": False, "size": 2048},
            ],
        }

        result = detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/models/", api_token="test-token")

        assert result["type"] == "folder"
        assert len(result["children"]) == 3
        assert result["repo"] == "my-repo"

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_detect_jfrog_target_type_auth_error(self, mock_get):
        """Test handling of authentication errors."""
        mock_response = mock_get.return_value
        from unittest.mock import Mock

        mock_error_response = Mock(spec=requests.Response)
        mock_error_response.status_code = 401
        http_error = requests.exceptions.HTTPError(response=mock_error_response)
        mock_response.raise_for_status.side_effect = http_error

        with pytest.raises(Exception, match="Authentication failed"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/model.pkl")

    @patch("modelaudit.utils.jfrog.requests.get")
    def test_detect_jfrog_target_type_not_found(self, mock_get):
        """Test handling of 404 errors."""
        mock_response = mock_get.return_value
        from unittest.mock import Mock

        mock_error_response = Mock(spec=requests.Response)
        mock_error_response.status_code = 404
        http_error = requests.exceptions.HTTPError(response=mock_error_response)
        mock_response.raise_for_status.side_effect = http_error

        with pytest.raises(Exception, match="not found"):
            detect_jfrog_target_type("https://company.jfrog.io/artifactory/repo/nonexistent.pkl")


class TestJFrogFolderListing:
    """Test JFrog folder content listing."""

    @patch("modelaudit.utils.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_simple(self, mock_detect):
        """Test listing contents of a simple folder."""
        # Mock folder with files
        mock_detect.return_value = {
            "type": "folder",
            "children": [
                {"uri": "/model1.pkl", "folder": False, "size": 1024},
                {"uri": "/model2.pt", "folder": False, "size": 2048},
                {"uri": "/readme.txt", "folder": False, "size": 256},
            ],
        }

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/",
            api_token="test-token",
            recursive=False,
            selective=True,  # Filter to only scannable files
        )

        # Should filter out readme.txt, keep only model files
        assert len(files) == 2
        file_names = {f["name"] for f in files}
        assert file_names == {"model1.pkl", "model2.pt"}

        # Check file details
        pkl_file = next(f for f in files if f["name"] == "model1.pkl")
        assert pkl_file["size"] == 1024
        assert pkl_file["human_size"] == "1.0 KB"

    @patch("modelaudit.utils.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_recursive(self, mock_detect):
        """Test recursive listing of nested folders."""

        def mock_detect_side_effect(url, *args, **kwargs):
            if url.endswith("models/") or url.endswith("models"):
                return {
                    "type": "folder",
                    "children": [
                        {"uri": "/model1.pkl", "folder": False, "size": 1024},
                        {"uri": "/pytorch", "folder": True},
                    ],
                }
            elif url.endswith("/pytorch") or url.endswith("pytorch"):
                return {"type": "folder", "children": [{"uri": "/model2.pt", "folder": False, "size": 2048}]}
            else:
                return {"type": "file"}

        mock_detect.side_effect = mock_detect_side_effect

        files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/", api_token="test-token", recursive=True, selective=False
        )

        # Should find files in both root and subfolder (before filtering)
        assert len(files) == 2
        file_names = {f["name"] for f in files}
        assert file_names == {"model1.pkl", "model2.pt"}

        # Test with filtering enabled
        filtered_files = list_jfrog_folder_contents(
            "https://company.jfrog.io/artifactory/repo/models/", api_token="test-token", recursive=True, selective=True
        )
        # Should still find the same files since they are scannable model files
        assert len(filtered_files) == 2

    @patch("modelaudit.utils.jfrog.detect_jfrog_target_type")
    def test_list_jfrog_folder_contents_not_folder(self, mock_detect):
        """Test error when trying to list contents of a file."""
        mock_detect.return_value = {"type": "file", "size": 1024}

        with pytest.raises(ValueError, match="not a JFrog folder"):
            list_jfrog_folder_contents("https://company.jfrog.io/artifactory/repo/model.pkl")


class TestJFrogFolderDownload:
    """Test JFrog folder download functionality."""

    @patch("modelaudit.utils.jfrog.download_artifact")
    @patch("modelaudit.utils.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_success(self, mock_list, mock_download, tmp_path):
        """Test successful folder download."""
        # Mock folder contents
        mock_list.return_value = [
            {
                "name": "model1.pkl",
                "path": "https://company.jfrog.io/artifactory/repo/models/model1.pkl",
                "size": 1024,
                "human_size": "1.0 KB",
            },
            {
                "name": "model2.pt",
                "path": "https://company.jfrog.io/artifactory/repo/models/model2.pt",
                "size": 2048,
                "human_size": "2.0 KB",
            },
        ]

        # Mock individual file downloads
        def mock_download_side_effect(url, cache_dir, **kwargs):
            filename = Path(url).name
            downloaded_file = cache_dir / filename
            downloaded_file.write_bytes(b"mock file content")
            return downloaded_file

        mock_download.side_effect = mock_download_side_effect

        result_dir = download_jfrog_folder(
            "https://company.jfrog.io/artifactory/repo/models/", cache_dir=tmp_path, api_token="test-token"
        )

        assert result_dir == tmp_path
        assert len(list(tmp_path.glob("**/*"))) >= 2  # At least 2 files downloaded

    @patch("modelaudit.utils.jfrog.list_jfrog_folder_contents")
    def test_download_jfrog_folder_no_files(self, mock_list):
        """Test error when no scannable files found."""
        mock_list.return_value = []  # No files after filtering

        with pytest.raises(ValueError, match="No scannable model files found"):
            download_jfrog_folder("https://company.jfrog.io/artifactory/repo/empty-folder/")
