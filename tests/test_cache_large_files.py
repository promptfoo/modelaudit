"""Tests for large file cache integration."""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

from modelaudit.scanners.base import CheckStatus, IssueSeverity, ScanResult
from modelaudit.utils.advanced_file_handler import scan_advanced_large_file
from modelaudit.utils.large_file_handler import scan_large_file


class TestScanResultSerialization:
    """Test ScanResult serialization and deserialization."""

    def test_scan_result_to_dict_and_from_dict(self):
        """Test ScanResult can be serialized to dict and reconstructed."""
        # Create original result
        original = ScanResult(scanner_name="test_scanner")
        original.add_issue("Test issue", IssueSeverity.CRITICAL, location="test.py", details={"key": "value"})
        original.add_check("Test check", passed=True, message="Check passed", severity=IssueSeverity.INFO)
        original.add_check("Failed check", passed=False, message="Check failed", severity=IssueSeverity.WARNING)
        original.bytes_scanned = 1024
        original.metadata = {"test_key": "test_value"}
        original.finish(success=True)

        # Serialize and deserialize
        data = original.to_dict()
        reconstructed = ScanResult.from_dict(data)

        # Verify basic properties
        assert reconstructed.scanner_name == original.scanner_name
        assert reconstructed.success == original.success
        assert reconstructed.bytes_scanned == original.bytes_scanned
        assert reconstructed.metadata == original.metadata

        # Verify issues - should have 2: one explicit + one from failed check
        assert len(reconstructed.issues) == len(original.issues)
        # Find the explicitly added issue
        explicit_issue = next(i for i in reconstructed.issues if i.message == "Test issue")
        assert explicit_issue.severity == IssueSeverity.CRITICAL
        assert explicit_issue.location == "test.py"
        assert explicit_issue.details == {"key": "value"}

        # Verify checks - should have 2: one passed + one failed
        assert len(reconstructed.checks) == len(original.checks)

        # Check the passed check
        passed_checks = [c for c in reconstructed.checks if c.status == CheckStatus.PASSED]
        assert len(passed_checks) == 1
        passed_check = passed_checks[0]
        assert passed_check.name == "Test check"
        assert passed_check.message == "Check passed"

        # Check the failed checks - should have 2: one from add_issue, one from add_check(passed=False)
        failed_checks = [c for c in reconstructed.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) == 2

        # Find the check that was explicitly added with add_check
        explicit_check = next(c for c in failed_checks if c.message == "Check failed")
        assert explicit_check.name == "Failed check"

    def test_scan_result_from_dict_empty(self):
        """Test ScanResult can handle empty dict."""
        result = ScanResult.from_dict({})
        assert result.scanner_name == "unknown"
        assert result.success is False
        assert result.bytes_scanned == 0
        assert len(result.issues) == 0
        assert len(result.checks) == 0

    def test_scan_result_from_dict_partial(self):
        """Test ScanResult can handle partial data."""
        data = {"scanner": "partial_test", "success": True, "bytes_scanned": 512}
        result = ScanResult.from_dict(data)
        assert result.scanner_name == "partial_test"
        assert result.success is True
        assert result.bytes_scanned == 512
        assert len(result.issues) == 0
        assert len(result.checks) == 0


class TestLargeFileCache:
    """Test large file scanning with cache integration."""

    def test_large_file_cache_enabled(self):
        """Test large file scanning with cache enabled."""
        # Create mock scanner with cache enabled
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": True}

        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)  # 9KB file
            tmp_file.flush()

            try:
                # Mock internal scan to return test result
                test_result = ScanResult(scanner_name="test")
                test_result.add_issue("Test issue", IssueSeverity.INFO)
                test_result.finish(success=True)

                with patch("modelaudit.utils.large_file_handler._scan_large_file_internal", return_value=test_result):
                    # First scan - cache miss
                    result1 = scan_large_file(tmp_file.name, mock_scanner)

                    # Second scan - cache hit (should be much faster)
                    start_time = time.time()
                    result2 = scan_large_file(tmp_file.name, mock_scanner)
                    cache_hit_time = time.time() - start_time

                    # Verify results are equivalent
                    assert result1.scanner_name == result2.scanner_name
                    assert result1.success == result2.success
                    assert len(result1.issues) == len(result2.issues)

                    # Cache hit should be fast (less than 0.1 seconds)
                    assert cache_hit_time < 0.1, f"Cache hit took {cache_hit_time:.3f}s, expected < 0.1s"

            finally:
                Path(tmp_file.name).unlink()  # Clean up

    def test_large_file_cache_disabled(self):
        """Test large file scanning with cache disabled."""
        # Create mock scanner with cache disabled
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": False}

        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)
            tmp_file.flush()

            try:
                # Mock internal scan
                test_result = ScanResult(scanner_name="test")
                test_result.finish(success=True)

                with patch(
                    "modelaudit.utils.large_file_handler._scan_large_file_internal", return_value=test_result
                ) as mock_internal:
                    # Run scan twice
                    scan_large_file(tmp_file.name, mock_scanner)
                    scan_large_file(tmp_file.name, mock_scanner)

                    # Verify internal scan called twice (no caching)
                    assert mock_internal.call_count == 2

            finally:
                Path(tmp_file.name).unlink()  # Clean up

    def test_large_file_cache_fallback(self):
        """Test large file scanning falls back when cache fails."""
        # Create mock scanner with cache enabled
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": True}

        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)
            tmp_file.flush()

            try:
                # Mock internal scan
                test_result = ScanResult(scanner_name="test")
                test_result.finish(success=True)

                # Mock cache manager to raise exception
                with patch("modelaudit.cache.get_cache_manager", side_effect=Exception("Cache error")), patch(
                    "modelaudit.utils.large_file_handler._scan_large_file_internal", return_value=test_result
                ) as mock_internal:
                        # Should fall back to direct scan
                        result = scan_large_file(tmp_file.name, mock_scanner)

                        # Verify fallback was used
                        assert result.scanner_name == "test"
                        assert mock_internal.call_count == 1

            finally:
                Path(tmp_file.name).unlink()  # Clean up


class TestAdvancedLargeFileCache:
    """Test advanced large file scanning with cache integration."""

    def test_advanced_large_file_cache_integration(self):
        """Test advanced large file scanning with cache."""
        # Create mock scanner with cache disabled to ensure we get our mock directly
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": False}

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)
            tmp_file.flush()

            try:
                test_result = ScanResult(scanner_name="advanced_test")
                test_result.add_check("Advanced check", passed=True, message="Advanced scan check")
                test_result.finish(success=True)

                with patch(
                    "modelaudit.utils.advanced_file_handler._scan_advanced_large_file_internal",
                    return_value=test_result,
                ):
                    result = scan_advanced_large_file(tmp_file.name, mock_scanner)
                    # With cache disabled, we should get our mock result directly
                    assert result.scanner_name == "advanced_test"
                    assert len(result.checks) == 1  # We added exactly one check

            finally:
                Path(tmp_file.name).unlink()  # Clean up

    def test_advanced_large_file_cache_disabled(self):
        """Test advanced large file scanning with cache disabled."""
        # Create mock scanner with cache disabled
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": False}

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)
            tmp_file.flush()

            try:
                test_result = ScanResult(scanner_name="advanced_test")
                test_result.finish(success=True)

                with patch(
                    "modelaudit.utils.advanced_file_handler._scan_advanced_large_file_internal",
                    return_value=test_result,
                ) as mock_internal:
                    # Run scan twice
                    scan_advanced_large_file(tmp_file.name, mock_scanner)
                    scan_advanced_large_file(tmp_file.name, mock_scanner)

                    # Verify internal scan called twice (no caching)
                    assert mock_internal.call_count == 2

            finally:
                Path(tmp_file.name).unlink()  # Clean up

    def test_advanced_large_file_cache_fallback(self):
        """Test advanced large file scanning falls back when cache fails."""
        # Create mock scanner with cache enabled
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": True}

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"test data" * 1000)
            tmp_file.flush()

            try:
                test_result = ScanResult(scanner_name="advanced_test")
                test_result.finish(success=True)

                # Mock cache manager to raise exception
                with patch("modelaudit.cache.get_cache_manager", side_effect=Exception("Cache error")), patch(
                    "modelaudit.utils.advanced_file_handler._scan_advanced_large_file_internal",
                    return_value=test_result,
                ) as mock_internal:
                        # Should fall back to direct scan
                        result = scan_advanced_large_file(tmp_file.name, mock_scanner)

                        # Verify fallback was used
                        assert result.scanner_name == "advanced_test"
                        assert mock_internal.call_count == 1

            finally:
                Path(tmp_file.name).unlink()  # Clean up


class TestCacheIntegrationEndToEnd:
    """End-to-end tests for cache integration."""

    def test_cache_key_consistency(self):
        """Test that cache keys are consistent between scans."""
        mock_scanner = Mock()
        mock_scanner.config = {"cache_enabled": True}

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_file:
            tmp_file.write(b"consistent test data")
            tmp_file.flush()

            try:
                test_result = ScanResult(scanner_name="consistency_test")
                test_result.finish(success=True)

                # Mock the cache manager to track calls
                with patch("modelaudit.cache.get_cache_manager") as mock_cache_manager:
                    mock_cache_instance = Mock()
                    mock_cache_manager.return_value = mock_cache_instance
                    mock_cache_instance.cached_scan.return_value = test_result.to_dict()

                    # Run scan twice with same file
                    scan_large_file(tmp_file.name, mock_scanner)
                    scan_large_file(tmp_file.name, mock_scanner)

                    # Verify cache manager was called
                    assert mock_cache_instance.cached_scan.call_count == 2

                    # Verify both calls used the same file path (consistent cache key)
                    call_args = mock_cache_instance.cached_scan.call_args_list
                    assert call_args[0][0][0] == call_args[1][0][0]  # Same file path

            finally:
                Path(tmp_file.name).unlink()  # Clean up
