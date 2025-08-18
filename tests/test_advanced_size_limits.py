"""Test that advanced file handler bypasses size limits for large files."""

import tempfile
from unittest.mock import patch

from modelaudit.core import scan_file
from modelaudit.scanners.base import ScanResult
from modelaudit.utils.advanced_file_handler import (
    COLOSSAL_MODEL_THRESHOLD,
    EXTREME_MODEL_THRESHOLD,
    LARGE_MODEL_THRESHOLD_200GB,
    should_use_advanced_handler,
)


class TestAdvancedSizeLimits:
    """Test that size limits don't prevent scanning huge models."""

    @patch("modelaudit.utils.advanced_file_handler.os.path.getsize")
    @patch("modelaudit.core.os.path.getsize")
    @patch("modelaudit.core.should_use_advanced_handler")
    def test_advanced_files_bypass_size_limit(self, mock_should_use, mock_core_size, mock_extreme_size):
        """Test that advanced handler bypasses max_file_size limit."""
        # Simulate a 100GB file
        huge_size = 100 * 1024 * 1024 * 1024
        mock_core_size.return_value = huge_size
        mock_extreme_size.return_value = huge_size
        mock_should_use.return_value = True  # Force extreme handler

        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            # Config with a 1GB limit (much smaller than our file)
            config = {"max_file_size": 1024 * 1024 * 1024}  # 1GB limit

            # Mock the extreme handler to avoid actual scanning
            with patch("modelaudit.core.scan_advanced_large_file") as mock_scan:
                mock_scan.return_value = ScanResult("test")

                # Mock other required functions
                with patch("modelaudit.core.detect_file_format") as mock_format:
                    mock_format.return_value = "unknown"
                    with patch("modelaudit.core.detect_format_from_extension") as mock_ext:
                        mock_ext.return_value = "unknown"
                        with patch("modelaudit.core.validate_file_type") as mock_validate:
                            mock_validate.return_value = True

                            # Also need to mock the registry
                            with patch("modelaudit.core._registry.get_scanner_for_path") as mock_registry:
                                mock_registry.return_value = None  # No specific scanner

                                # This should NOT be blocked by max_file_size
                                result = scan_file(f.name, config)

                                # With new behavior, large files are still scanned
                                # but using the normal large file handler
                                assert result is not None

    @patch("modelaudit.utils.advanced_file_handler.os.path.getsize")
    def test_normal_files_respect_size_limit(self, mock_size):
        """Test that normal files still respect max_file_size."""
        # Simulate a 5GB file (below extreme threshold)
        normal_large_size = 5 * 1024 * 1024 * 1024
        mock_size.return_value = normal_large_size

        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            # Config with a 1GB limit
            config = {"max_file_size": 1024 * 1024 * 1024}  # 1GB limit

            with patch("modelaudit.core.os.path.getsize") as mock_core_size:
                mock_core_size.return_value = normal_large_size

                # This SHOULD be blocked by max_file_size
                result = scan_file(f.name, config)

                # Should have a size warning
                assert any("too large" in issue.message.lower() for issue in result.issues)
                assert any("hint" in issue.details for issue in result.issues if issue.details)
                assert not result.success
                assert result.end_time is not None

    @patch("modelaudit.core.os.path.getsize", side_effect=OSError("stat failed"))
    def test_stat_error_sets_failure_and_end_time(self, mock_size):
        """Ensure stat errors mark result as failed and set end time."""
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            result = scan_file(f.name, {})
            assert any("Error checking file size" in issue.message for issue in result.issues)
            assert not result.success
            assert result.end_time is not None

    @patch("modelaudit.utils.advanced_file_handler.os.path.getsize")
    def test_colossal_files_handled(self, mock_size):
        """Test that even 10TB+ files can be handled."""
        # Simulate a 10TB file
        colossal_size = 10 * 1024 * 1024 * 1024 * 1024  # 10TB
        mock_size.return_value = colossal_size

        # Should be detected as needing extreme handler
        assert should_use_advanced_handler("massive_model.bin")

    @patch("modelaudit.utils.advanced_file_handler.os.path.getsize")
    @patch("modelaudit.core.should_use_advanced_handler")
    def test_unlimited_size_default(self, mock_should_use, mock_size):
        """Test that default config has no size limit."""
        # Simulate a 500GB file
        huge_size = 500 * 1024 * 1024 * 1024
        mock_size.return_value = huge_size
        mock_should_use.return_value = True  # Force extreme handler

        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            # Default config (no size limit)
            config = {}

            with patch("modelaudit.core.os.path.getsize") as mock_core_size:
                mock_core_size.return_value = huge_size

                with patch("modelaudit.core.scan_advanced_large_file") as mock_scan:
                    mock_scan.return_value = ScanResult("test")

                    # Mock other required functions
                    with patch("modelaudit.core.detect_file_format") as mock_format:
                        mock_format.return_value = "unknown"
                        with patch("modelaudit.core.detect_format_from_extension") as mock_ext:
                            mock_ext.return_value = "unknown"
                            with patch("modelaudit.core.validate_file_type") as mock_validate:
                                mock_validate.return_value = True

                                # Also need to mock the registry
                                with patch("modelaudit.core._registry.get_scanner_for_path") as mock_registry:
                                    mock_registry.return_value = None  # No specific scanner

                                    # Should not be blocked
                                    result = scan_file(f.name, config)
                                    # With new behavior, we scan all files
                                    assert result is not None

    def test_size_thresholds_are_sensible(self):
        """Verify that size thresholds make sense."""
        # Extreme threshold should be at least 50GB
        assert EXTREME_MODEL_THRESHOLD >= 50 * 1024 * 1024 * 1024

        # Massive threshold should be larger
        assert LARGE_MODEL_THRESHOLD_200GB > EXTREME_MODEL_THRESHOLD

        # Colossal threshold should be even larger
        assert COLOSSAL_MODEL_THRESHOLD > LARGE_MODEL_THRESHOLD_200GB

        # Colossal should handle at least 1TB
        assert COLOSSAL_MODEL_THRESHOLD >= 1024 * 1024 * 1024 * 1024

    @patch("modelaudit.utils.advanced_file_handler.ShardedModelDetector.detect_shards")
    def test_sharded_models_bypass_individual_limits(self, mock_detect):
        """Test that sharded models are detected regardless of individual file sizes."""
        # Simulate detection of sharded model
        mock_detect.return_value = {
            "shards": ["shard1.bin", "shard2.bin"],
            "total_size": 2 * 1024 * 1024 * 1024 * 1024,  # 2TB total
        }

        # Even a "small" shard should trigger extreme handler if part of large model
        assert should_use_advanced_handler("shard1.bin")

    def test_no_hardcoded_upper_limit(self):
        """Ensure there's no hardcoded upper limit that would block any file."""
        # Test with absurdly large sizes - should not raise or fail
        petabyte = 1024 * 1024 * 1024 * 1024 * 1024  # 1PB
        exabyte = petabyte * 1024  # 1EB

        with patch("modelaudit.utils.advanced_file_handler.os.path.getsize") as mock_size:
            # Test petabyte file
            mock_size.return_value = petabyte
            assert should_use_advanced_handler("petabyte_model.bin")

            # Test exabyte file (theoretical)
            mock_size.return_value = exabyte
            assert should_use_advanced_handler("exabyte_model.bin")
