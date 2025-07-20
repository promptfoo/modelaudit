"""Tests for disk space utilities."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from modelaudit.utils.disk_space import (
    check_disk_space,
    format_bytes,
    get_free_space_bytes,
)


class TestDiskSpaceUtils:
    """Test disk space utility functions."""

    def test_format_bytes(self):
        """Test byte formatting."""
        assert format_bytes(0) == "0.0 B"
        assert format_bytes(1023) == "1023.0 B"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"
        assert format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"
        assert format_bytes(1536) == "1.5 KB"
        assert format_bytes(-1024) == "-1.0 KB"

    @patch("modelaudit.utils.disk_space.shutil.disk_usage")
    def test_get_free_space_bytes(self, mock_disk_usage):
        """Test getting free space."""
        mock_usage = Mock()
        mock_usage.free = 1024 * 1024 * 1024  # 1 GB
        mock_disk_usage.return_value = mock_usage

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            free_space = get_free_space_bytes(path)
            assert free_space == 1024 * 1024 * 1024
            mock_disk_usage.assert_called_once()

    @patch("modelaudit.utils.disk_space.get_free_space_bytes")
    def test_check_disk_space_sufficient(self, mock_get_free_space):
        """Test disk space check when space is sufficient."""
        mock_get_free_space.return_value = 2 * 1024 * 1024 * 1024  # 2 GB

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Request 1 GB with 1.2x safety margin = 1.2 GB needed
            has_space, message = check_disk_space(path, 1024 * 1024 * 1024)

            assert has_space is True
            assert "Sufficient disk space available" in message
            assert "2.0 GB" in message

    @patch("modelaudit.utils.disk_space.get_free_space_bytes")
    def test_check_disk_space_insufficient(self, mock_get_free_space):
        """Test disk space check when space is insufficient."""
        mock_get_free_space.return_value = 1024 * 1024 * 1024  # 1 GB

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Request 1 GB with 1.2x safety margin = 1.2 GB needed
            has_space, message = check_disk_space(path, 1024 * 1024 * 1024)

            assert has_space is False
            assert "Insufficient disk space" in message
            assert "Required: 1.2 GB" in message
            assert "Available: 1.0 GB" in message
            assert "safety margin" in message

    @patch("modelaudit.utils.disk_space.get_free_space_bytes")
    def test_check_disk_space_custom_margin(self, mock_get_free_space):
        """Test disk space check with custom safety margin."""
        mock_get_free_space.return_value = 1600 * 1024 * 1024  # 1.6 GB

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            # Request 1 GB with 1.5x safety margin = 1.5 GB needed
            has_space, message = check_disk_space(path, 1024 * 1024 * 1024, safety_margin=1.5)

            assert has_space is True  # More than enough space
            assert "Sufficient disk space available" in message
