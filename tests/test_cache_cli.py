"""Tests for cache CLI commands."""

import tempfile
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.cli import cli


class TestCacheCLI:
    """Test cache CLI commands."""

    def setup_method(self):
        """Reset cache manager before each test."""
        reset_cache_manager()

    def test_cache_stats_empty(self):
        """Test cache stats with empty cache."""
        with tempfile.TemporaryDirectory() as temp_dir:
            runner = CliRunner()
            result = runner.invoke(cli, ["cache", "stats", "--cache-dir", temp_dir])

            assert result.exit_code == 0
            assert "Cache Statistics" in result.output
            assert "Total entries: 0" in result.output
            assert "Hit rate: 0.0%" in result.output

    def test_cache_clear_dry_run(self):
        """Test cache clear dry run."""
        runner = CliRunner()
        result = runner.invoke(cli, ["cache", "clear", "--dry-run"])

        assert result.exit_code == 0
        assert "Would clear" in result.output

    def test_cache_clear_with_data(self):
        """Test cache clear with actual data."""
        # Reset global cache manager to ensure isolation
        reset_cache_manager()

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.NamedTemporaryFile(suffix=".pkl") as tmp_file:
            tmp_file.write(b"test content")
            tmp_file.flush()

            cache_manager = get_cache_manager(cache_dir=temp_dir, enabled=True)
            test_result = {"test": "result", "findings": []}
            cache_manager.store_result(tmp_file.name, test_result, 100)

            # Check stats show entry
            runner = CliRunner()
            result = runner.invoke(cli, ["cache", "stats", "--cache-dir", temp_dir])
            assert "Total entries: 1" in result.output

            # Clear cache
            result = runner.invoke(cli, ["cache", "clear", "--cache-dir", temp_dir])
            assert result.exit_code == 0
            assert "Cleared 1 cache entries" in result.output

            # Verify cleared
            result = runner.invoke(cli, ["cache", "stats", "--cache-dir", temp_dir])
            assert "Total entries: 0" in result.output

    def test_cache_cleanup_dry_run(self):
        """Test cache cleanup dry run."""
        runner = CliRunner()
        result = runner.invoke(cli, ["cache", "cleanup", "--dry-run", "--max-age", "7"])

        assert result.exit_code == 0
        assert "Would cleanup cache entries older than 7 days" in result.output

    def test_cache_cleanup_with_max_age(self):
        """Test cache cleanup with custom max age."""
        runner = CliRunner()
        result = runner.invoke(cli, ["cache", "cleanup", "--max-age", "60"])

        assert result.exit_code == 0
        # Should either report removed count or no entries found
        assert ("Removed" in result.output) or ("No old cache entries found" in result.output)

    def test_cache_clear_with_custom_dir(self, tmp_path):
        """Test cache clear with custom cache directory."""
        cache_dir = tmp_path / "custom_cache"
        cache_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(cli, ["cache", "clear", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert "Cleared" in result.output

    def test_cache_stats_with_custom_dir(self, tmp_path):
        """Test cache stats with custom cache directory."""
        cache_dir = tmp_path / "custom_cache"
        cache_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(cli, ["cache", "stats", "--cache-dir", str(cache_dir)])

        assert result.exit_code == 0
        assert "Cache Statistics" in result.output

    def test_cache_error_handling(self):
        """Test cache commands handle errors gracefully."""
        with patch("modelaudit.cache.get_cache_manager") as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.get_stats.side_effect = Exception("Test error")
            mock_get_manager.return_value = mock_manager

            runner = CliRunner()
            result = runner.invoke(cli, ["cache", "stats"])

            assert result.exit_code == 1
            assert "Failed to get cache stats" in result.output

    def test_cache_help_commands(self):
        """Test help output for cache commands."""
        runner = CliRunner()

        # Test cache group help
        result = runner.invoke(cli, ["cache", "--help"])
        assert result.exit_code == 0
        assert "Manage scan results cache" in result.output
        assert "clear" in result.output
        assert "stats" in result.output
        assert "cleanup" in result.output

        # Test clear help
        result = runner.invoke(cli, ["cache", "clear", "--help"])
        assert result.exit_code == 0
        assert "Clear the entire scan results cache" in result.output
        assert "--dry-run" in result.output

        # Test stats help
        result = runner.invoke(cli, ["cache", "stats", "--help"])
        assert result.exit_code == 0
        assert "Show cache statistics" in result.output

        # Test cleanup help
        result = runner.invoke(cli, ["cache", "cleanup", "--help"])
        assert result.exit_code == 0
        assert "Clean up old cache entries" in result.output
        assert "--max-age" in result.output


def test_main_help_shows_cache_commands():
    """Test that main help shows cache commands."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "cache clear" in result.output
    assert "cache stats" in result.output


def test_scan_command_has_cache_options():
    """Test that scan command has cache options."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--cache / --no-cache" in result.output
    assert "--cache-dir" in result.output
