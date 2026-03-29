"""Tests for CLI cache_dir option."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from modelaudit.cli import cli
from modelaudit.models import ModelAuditResultModel, create_initial_audit_result


def create_mock_scan_result(**kwargs: Any) -> ModelAuditResultModel:
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
                why=None,
                type=None,
            )
            issues.append(issue)
        result.issues = issues

    result.finalize_statistics()
    return result


class TestCacheDirOption:
    """Test the --cache-dir option functionality."""

    def test_cache_dir_option_exists(self) -> None:
        """Test that cache directory option is available."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--cache-dir" in result.output
        assert "--no-cache" in result.output

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_huggingface_download_with_cache_dir(
        self,
        mock_scan: MagicMock,
        mock_is_hf_url: MagicMock,
        mock_download_model: MagicMock,
        mock_spinner: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test HuggingFace download uses automatic defaults for cache directory."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_model.return_value = mock_download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        runner = CliRunner()

        # With automatic defaults, HuggingFace URLs should enable caching automatically
        result = runner.invoke(cli, ["scan", "hf://test/model"])

        # Verify download was called (automatic defaults should provide cache_dir)
        mock_download_model.assert_called_once()
        call_kwargs = mock_download_model.call_args.kwargs
        assert "cache_dir" in call_kwargs  # Automatic defaults should provide cache_dir
        assert result.exit_code == 0

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_from_cloud")
    @patch("modelaudit.cli.is_cloud_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_cloud_download_with_cache_dir(
        self,
        mock_scan: MagicMock,
        mock_is_cloud_url: MagicMock,
        mock_download_cloud: MagicMock,
        mock_spinner: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test cloud storage download uses automatic defaults for cache directory."""
        # Setup mocks
        mock_is_cloud_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_cloud.return_value = mock_download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        runner = CliRunner()

        # With automatic defaults, cloud URLs should enable caching automatically
        result = runner.invoke(cli, ["scan", "s3://bucket/model.pt"])

        # Verify download was called (automatic defaults should provide cache_dir)
        mock_download_cloud.assert_called_once()
        call_kwargs = mock_download_cloud.call_args.kwargs
        assert "cache_dir" in call_kwargs  # Automatic defaults should provide cache_dir
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_no_cleanup_with_cache_dir(
        self,
        mock_rmtree: MagicMock,
        mock_scan: MagicMock,
        mock_is_hf_url: MagicMock,
        mock_download_model: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that temporary directories are not cleaned up when using automatic-defaults caching."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        cache_dir = tmp_path / "auto_cache"
        download_path = cache_dir / "model"
        download_path.mkdir(parents=True)
        mock_download_model.return_value = download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        runner = CliRunner()

        # With automatic defaults, HuggingFace URLs enable caching by default (no cleanup)
        result = runner.invoke(cli, ["scan", "hf://test/model"])

        # Verify cleanup was NOT called since automatic defaults enable caching
        mock_rmtree.assert_not_called()
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_cleanup_without_cache_dir(
        self,
        mock_rmtree: MagicMock,
        mock_scan: MagicMock,
        mock_is_hf_url: MagicMock,
        mock_download_model: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that no-cache HuggingFace scans clean up the private temp cache directory they create."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        temp_download_path = tmp_path / "temp_model"
        temp_download_path.mkdir()
        mock_download_model.return_value = temp_download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        runner = CliRunner()

        result = runner.invoke(
            cli,
            ["scan", "--no-cache", "hf://test/model"],  # No --cache-dir option, disable caching
        )

        # Verify the downloader used a private temp cache dir and CLI cleaned it up.
        cache_dir = mock_download_model.call_args.kwargs["cache_dir"]
        assert cache_dir is not None
        assert cache_dir.name.startswith("modelaudit_hf_")
        mock_rmtree.assert_called_once_with(str(cache_dir))
        assert result.exit_code == 0

    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    def test_disk_space_error_message_mentions_cache_dir(
        self, mock_is_hf_url: MagicMock, mock_download_model: MagicMock
    ) -> None:
        """Test that disk space error messages mention --cache-dir option."""
        # Setup mocks
        mock_is_hf_url.return_value = True
        mock_download_model.side_effect = Exception(
            "Cannot download model: Insufficient disk space. Required: 10GB, Available: 5GB"
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "hf://test/model"])

        # Verify the error message mentions --cache-dir and disk space guidance
        assert "--cache-dir" in result.output
        # The actual message is "Tip: Use --stream to minimize disk usage, or use --cache-dir..."
        assert "disk" in result.output.lower()
        assert result.exit_code != 0

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_explicit_cache_dir_flag(
        self,
        mock_scan: MagicMock,
        mock_is_hf_url: MagicMock,
        mock_download_model: MagicMock,
        mock_spinner: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that --cache-dir flag sets cache_dir and enables caching."""
        mock_is_hf_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_model.return_value = mock_download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        cache_path = tmp_path / "my_cache"
        cache_path.mkdir()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--cache-dir", str(cache_path), "hf://test/model"])

        assert result.exit_code == 0
        mock_download_model.assert_called_once()
        call_kwargs = mock_download_model.call_args.kwargs
        assert "cache_dir" in call_kwargs

    @patch("modelaudit.cli.should_show_spinner", return_value=False)
    @patch("modelaudit.cli.download_model")
    @patch("modelaudit.cli.is_huggingface_url")
    @patch("modelaudit.cli.scan_model_directory_or_file")
    @patch("shutil.rmtree")
    def test_no_cache_overrides_cache_dir(
        self,
        mock_rmtree: MagicMock,
        mock_scan: MagicMock,
        mock_is_hf_url: MagicMock,
        mock_download_model: MagicMock,
        mock_spinner: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that --no-cache takes precedence over --cache-dir and avoids persisting downloads there."""
        mock_is_hf_url.return_value = True
        mock_download_path = tmp_path / "downloaded_model"
        mock_download_path.mkdir()
        mock_download_model.return_value = mock_download_path
        mock_scan.return_value = create_mock_scan_result(success=True, issues=[])

        cache_path = tmp_path / "my_cache"
        cache_path.mkdir()

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--cache-dir", str(cache_path), "--no-cache", "hf://test/model"])

        assert result.exit_code == 0
        call_kwargs = mock_download_model.call_args.kwargs
        cache_dir = call_kwargs["cache_dir"]
        assert cache_dir != cache_path
        assert cache_dir.name.startswith("modelaudit_hf_")
        mock_rmtree.assert_called_once_with(str(cache_dir))
