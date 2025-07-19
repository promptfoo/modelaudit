"""Tests for parallel scanning CLI flags."""

from unittest.mock import patch

from click.testing import CliRunner

from modelaudit.cli import cli


class TestParallelScanningCLI:
    """Test parallel scanning command line options."""

    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_default_parallel_scanning(self, mock_scan):
        """Test that parallel scanning is enabled by default."""
        # Setup mock
        mock_scan.return_value = {
            "success": True,
            "issues": [],
            "files_scanned": 10,
            "assets": [],
            "bytes_scanned": 1000,
            "scanners": ["test"],
            "parallel_scan": True,
            "worker_count": 4,
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create a test file
            with open("test.pkl", "wb") as f:
                f.write(b"test")

            result = runner.invoke(cli, ["scan", "test.pkl"])

        # Check that scan was called with parallel=True
        mock_scan.assert_called_once()
        call_kwargs = mock_scan.call_args.kwargs
        assert call_kwargs.get("parallel") is True
        assert result.exit_code == 0

    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_no_parallel_flag(self, mock_scan):
        """Test --no-parallel flag disables parallel scanning."""
        # Setup mock
        mock_scan.return_value = {
            "success": True,
            "issues": [],
            "files_scanned": 1,
            "assets": [],
            "bytes_scanned": 100,
            "scanners": ["test"],
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create a test file
            with open("test.pkl", "wb") as f:
                f.write(b"test")

            result = runner.invoke(cli, ["scan", "--no-parallel", "test.pkl"])

        # Check that scan was called with parallel=False
        mock_scan.assert_called_once()
        call_kwargs = mock_scan.call_args.kwargs
        assert call_kwargs.get("parallel") is False
        assert result.exit_code == 0

    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_concurrency_short_flag(self, mock_scan):
        """Test -j flag sets worker count."""
        # Setup mock
        mock_scan.return_value = {
            "success": True,
            "issues": [],
            "files_scanned": 10,
            "assets": [],
            "bytes_scanned": 1000,
            "scanners": ["test"],
            "parallel_scan": True,
            "worker_count": 8,
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create a test file
            with open("test.pkl", "wb") as f:
                f.write(b"test")

            result = runner.invoke(cli, ["scan", "-j", "8", "test.pkl"])

        # Check that scan was called with max_workers=8
        mock_scan.assert_called_once()
        call_kwargs = mock_scan.call_args.kwargs
        assert call_kwargs.get("max_workers") == 8
        assert call_kwargs.get("parallel") is True
        assert result.exit_code == 0

    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_concurrency_long_flag(self, mock_scan):
        """Test --concurrency flag sets worker count."""
        # Setup mock
        mock_scan.return_value = {
            "success": True,
            "issues": [],
            "files_scanned": 20,
            "assets": [],
            "bytes_scanned": 2000,
            "scanners": ["test"],
            "parallel_scan": True,
            "worker_count": 16,
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create a test file
            with open("test.pkl", "wb") as f:
                f.write(b"test")

            result = runner.invoke(cli, ["scan", "--concurrency", "16", "test.pkl"])

        # Check that scan was called with max_workers=16
        mock_scan.assert_called_once()
        call_kwargs = mock_scan.call_args.kwargs
        assert call_kwargs.get("max_workers") == 16
        assert call_kwargs.get("parallel") is True
        assert result.exit_code == 0

    @patch("modelaudit.cli.scan_model_directory_or_file")
    def test_parallel_scan_output_shows_worker_count(self, mock_scan):
        """Test that parallel scan output shows worker count in summary."""
        # Setup mock
        mock_scan.return_value = {
            "success": True,
            "issues": [],
            "files_scanned": 100,
            "assets": [],
            "bytes_scanned": 10000,
            "scanners": ["test"],
            "parallel_scan": True,
            "worker_count": 4,
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create a test file
            with open("test.pkl", "wb") as f:
                f.write(b"test")

            result = runner.invoke(cli, ["scan", "test.pkl"])

        # Check output contains parallel scan info
        assert "Parallel scan: Enabled (4 workers)" in result.output
        assert result.exit_code == 0

    def test_help_shows_parallel_options(self):
        """Test that help text shows parallel scanning options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "-j, --concurrency" in result.output
        assert "--no-parallel" in result.output
        assert "Number of worker processes" in result.output
        assert "Disable parallel scanning" in result.output
