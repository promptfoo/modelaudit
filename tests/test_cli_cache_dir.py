"""Tests for CLI cache_dir option."""

from unittest.mock import patch

from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.models import create_initial_audit_result


def create_mock_scan_result(**kwargs):
    """Create a mock ModelAuditResultModel for testing."""
    result = create_initial_audit_result()
    result.success = kwargs.get("success", True)
    result.has_errors = kwargs.get("has_errors", False)
    result.bytes_scanned = kwargs.get("bytes_scanned", 1024)
    result.files_scanned = kwargs.get("files_scanned", 1)

    # Add issues if provided
    if "issues" in kwargs:
        import time

        from modelaudit.scanners.base import Issue

        issues = []
        for issue_dict in kwargs["issues"]:
            issue = Issue(
                message=issue_dict.get("message", "Test issue"),
                severity=issue_dict.get("severity", "warning"),
                location=issue_dict.get("location"),
                timestamp=time.time(),
                details=issue_dict.get("details", {}),
            )
            issues.append(issue)
        result.issues = issues

    result.finalize_statistics()
    return result


class TestCacheDirOption:
    """Test the --cache-dir option functionality."""

    def test_cache_dir_option_exists(self):
        """Test that cache directory is handled via smart detection."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        # --cache-dir is now handled by smart detection, not a CLI flag
        assert "smart detection" in result.output.lower()
        assert "--no-cache" in result.output

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_huggingface_download_with_cache_dir(
        self, mock_scan, mock_is_hf_url, mock_download_model, mock_spinner
    ):
        """Test HuggingFace download uses smart detection for cache directory."""
        import os
        import tempfile
        import contextlib

        # Use tempfile.TemporaryDirectory to avoid pytest safe_tmp_path fixture issues
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup mocks
            mock_is_hf_url.return_value = True
            mock_download_path = os.path.join(temp_dir, "downloaded_model")
            os.makedirs(mock_download_path)
            mock_download_model.return_value = mock_download_path
            mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

            runner = CliRunner()

            # With smart detection, HuggingFace URLs should enable caching automatically
            result = runner.invoke(cli, ["scan", "hf://test/model"])

            # Verify download was called (smart detection should provide cache_dir)
            mock_download_model.assert_called_once()
            call_kwargs = mock_download_model.call_args.kwargs
            assert "cache_dir" in call_kwargs  # Smart detection should provide cache_dir
            assert result.exit_code == 0

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_from_cloud")
    @patch("modelaudit.cli.is_cloud_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_cloud_download_with_cache_dir(
        self, mock_scan, mock_is_cloud_url, mock_download_cloud, mock_spinner
    ):
        """Test cloud storage download uses smart detection for cache directory."""
        import os
        import tempfile

        # Use tempfile.TemporaryDirectory to avoid pytest safe_tmp_path fixture issues
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup mocks
            mock_is_cloud_url.return_value = True
            mock_download_path = os.path.join(temp_dir, "downloaded_model")
            os.makedirs(mock_download_path)
            mock_download_cloud.return_value = mock_download_path
            mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

            runner = CliRunner()

            # With smart detection, cloud URLs should enable caching automatically
            result = runner.invoke(cli, ["scan", "s3://bucket/model.pt"])

            # Verify download was called (smart detection should provide cache_dir)
            mock_download_cloud.assert_called_once()
            call_kwargs = mock_download_cloud.call_args.kwargs
            assert "cache_dir" in call_kwargs  # Smart detection should provide cache_dir
            assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_no_cleanup_with_cache_dir(self, mock_rmtree, mock_scan, mock_is_hf_url, mock_download_model):
        """Test that temporary directories are not cleaned up when using smart detection caching."""
        import os
        import tempfile

        # Use tempfile.TemporaryDirectory to avoid pytest safe_tmp_path fixture issues
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup mocks
            mock_is_hf_url.return_value = True
            cache_dir = os.path.join(temp_dir, "smart_cache")
            download_path = os.path.join(cache_dir, "model")
            os.makedirs(download_path)
            mock_download_model.return_value = download_path
            mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

            runner = CliRunner()

            # With smart detection, HuggingFace URLs enable caching by default (no cleanup)
            result = runner.invoke(cli, ["scan", "hf://test/model"])

            # Verify cleanup was NOT called since smart detection enables caching
            mock_rmtree.assert_not_called()
            assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_cleanup_without_cache_dir(self, mock_rmtree, mock_scan, mock_is_hf_url, mock_download_model):
        """Test that temporary directories ARE cleaned up when NOT using --cache-dir."""
        import os
        import tempfile

        # Use tempfile.TemporaryDirectory to avoid pytest safe_tmp_path fixture issues
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup mocks
            mock_is_hf_url.return_value = True
            temp_download_path = os.path.join(temp_dir, "temp_model")
            os.makedirs(temp_download_path)
            mock_download_model.return_value = temp_download_path
            mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

            runner = CliRunner()

            result = runner.invoke(
                cli,
                ["scan", "--no-cache", "hf://test/model"],  # No --cache-dir option, disable caching
            )

            # Verify cleanup WAS called since we didn't use a cache directory
            mock_rmtree.assert_called_once_with(temp_download_path)
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
