"""Tests for CLI cache_dir option."""

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from modelaudit.cli import cli


class TestCacheDirOption:
    """Test the --cache-dir option functionality."""

    def test_cache_dir_option_exists(self):
        """Test that --cache-dir option is available in CLI."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--cache-dir" in result.output
        assert "Directory for caching downloaded files" in result.output

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_huggingface_download_with_cache_dir(self, mock_scan, mock_is_hf_url, mock_download_model, tmp_path):
        """Test HuggingFace download uses specified cache directory."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_model.return_value = mock_download_path
        mock_scan.return_value = {"success": True, "issues": []}

        runner = CliRunner()
        cache_dir = tmp_path / "my_cache"

        result = runner.invoke(cli, ["scan", "hf://test/model", "--cache-dir", str(cache_dir)])

        # Verify download was called with the cache directory
        mock_download_model.assert_called_once_with(
            "hf://test/model", cache_dir=Path(str(cache_dir)), show_progress=True
        )
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_from_cloud")
    @patch("modelaudit.cli.is_cloud_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_cloud_download_with_cache_dir(self, mock_scan, mock_is_cloud_url, mock_download_cloud, tmp_path):
        """Test cloud storage download uses specified cache directory."""
        # Setup mocks
        mock_is_cloud_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_cloud.return_value = mock_download_path
        mock_scan.return_value = {"success": True, "issues": []}

        runner = CliRunner()
        cache_dir = tmp_path / "cloud_cache"

        result = runner.invoke(cli, ["scan", "s3://bucket/model.pt", "--cache-dir", str(cache_dir)])

        # Verify download was called with the cache directory
        mock_download_cloud.assert_called_once_with(
            "s3://bucket/model.pt",
            cache_dir=Path(str(cache_dir)),
            max_size=None,
            use_cache=True,
            show_progress=False,
            selective=True,
            stream_analyze=False,
        )
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_no_cleanup_with_cache_dir(self, mock_rmtree, mock_scan, mock_is_hf_url, mock_download_model, tmp_path):
        """Test that temporary directories are not cleaned up when using --cache-dir."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        cache_dir = tmp_path / "persistent_cache"
        download_path = cache_dir / "model"
        download_path.mkdir(parents=True)
        mock_download_model.return_value = download_path
        mock_scan.return_value = {"success": True, "issues": []}

        runner = CliRunner()

        result = runner.invoke(cli, ["scan", "hf://test/model", "--cache-dir", str(cache_dir)])

        # Verify cleanup was NOT called since we used a cache directory
        mock_rmtree.assert_not_called()
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_cleanup_without_cache_dir(self, mock_rmtree, mock_scan, mock_is_hf_url, mock_download_model, tmp_path):
        """Test that temporary directories ARE cleaned up when NOT using --cache-dir."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        temp_download_path = tmp_path / "temp_model"
        temp_download_path.mkdir()
        mock_download_model.return_value = temp_download_path
        mock_scan.return_value = {"success": True, "issues": []}

        runner = CliRunner()

        result = runner.invoke(
            cli,
            ["scan", "--no-cache", "hf://test/model"],  # No --cache-dir option, disable caching
        )

        # Verify cleanup WAS called since we didn't use a cache directory
        mock_rmtree.assert_called_once_with(str(temp_download_path))
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    def test_disk_space_error_message_mentions_cache_dir(self, mock_is_hf_url, mock_download_model):
        """Test that disk space error messages mention --cache-dir option."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        mock_download_model.side_effect = Exception(
            "Cannot download model: Insufficient disk space. Required: 10GB, Available: 5GB"
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "hf://test/model"])

        # Verify the error message mentions --cache-dir
        assert "--cache-dir" in result.output
        assert "Free up disk space" in result.output
        assert result.exit_code != 0
