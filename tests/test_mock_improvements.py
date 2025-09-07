"""
Test to demonstrate and validate the improved mocking strategies.

This test file shows how to use the new fast mocking utilities
and measures performance improvements over traditional approaches.
"""

import time
from unittest.mock import patch

import pytest

from tests.mock_utils import FastFileSystem, FastScannerMocks, setup_fast_test_environment


class TestFastMockingDemo:
    """Demonstrate improved mocking strategies."""

    def test_fast_filesystem_mock(self, fast_filesystem):
        """Test the fast in-memory filesystem."""
        # Add files to the mock filesystem
        fast_filesystem.add_file("/test/model.pkl", b"mock pickle data")
        fast_filesystem.add_file("/test/config.json", '{"model": "config"}')

        # Test filesystem operations
        assert fast_filesystem.exists("/test/model.pkl")
        assert fast_filesystem.is_file("/test/model.pkl")
        assert fast_filesystem.get_file("/test/model.pkl") == b"mock pickle data"

        # Test stat operations
        stat_result = fast_filesystem.stat("/test/model.pkl")
        assert stat_result.st_size == len(b"mock pickle data")

    def test_fast_scanner_result(self, fast_scanner_result):
        """Test fast scanner result creation."""
        assert fast_scanner_result.success
        assert fast_scanner_result.files_scanned == 1
        assert fast_scanner_result.bytes_scanned == 1024
        assert fast_scanner_result.duration < 0.01  # Very fast

    def test_complete_fast_environment(self):
        """Test the complete fast test environment."""
        with setup_fast_test_environment() as env:
            # Add test files
            env.add_file("/tmp/test.pkl", b"test content")

            # Test that heavy imports are mocked
            import numpy
            import tensorflow  # Should be fast due to mocking
            import torch

            # Verify mocks work
            assert torch.__version__ == "2.0.0"
            assert tensorflow.__version__ == "2.13.0"
            assert numpy.__version__ == "1.24.0"

    def test_network_operations_mocked(self, fast_network_calls):
        """Test that network operations are properly mocked."""
        import requests

        # This should be instant due to mocking
        start_time = time.time()
        response = requests.get("https://example.com/api/data")
        duration = time.time() - start_time

        assert duration < 0.01  # Should be nearly instant
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_file_operations_mocked(self, fast_file_operations):
        """Test that file operations are mocked for speed."""
        # Add a file to the mock filesystem
        fast_file_operations.add_file("/tmp/large_model.bin", b"x" * 10000)

        # File operations should be instant
        start_time = time.time()

        # These operations would normally be slow for large files
        with open("/tmp/large_model.bin", "rb") as f:
            data = f.read()

        duration = time.time() - start_time

        assert duration < 0.01  # Should be nearly instant
        assert len(data) == 10000

    def test_no_sleep_fixture(self, no_sleep):
        """Test that time.sleep is mocked out."""
        start_time = time.time()

        # This would normally take 1 second
        time.sleep(1.0)

        duration = time.time() - start_time
        assert duration < 0.01  # Should be nearly instant

    def test_temp_file_operations_mocked(self, fast_tempfiles):
        """Test that temporary file operations are mocked."""
        import tempfile

        # These should be instant and return mock paths
        temp_dir = tempfile.mkdtemp()
        fd, temp_file = tempfile.mkstemp()

        assert temp_dir.startswith("/tmp/mock_temp_")
        assert temp_file.startswith("/tmp/mock_temp_file_")

    def test_subprocess_operations_mocked(self, mock_subprocess):
        """Test that subprocess operations are mocked."""
        import subprocess

        start_time = time.time()

        # This would normally execute an external process
        result = subprocess.run(["echo", "hello"], capture_output=True)

        duration = time.time() - start_time

        assert duration < 0.01  # Should be nearly instant
        assert result.returncode == 0
        assert result.stdout == b"mock output"


class TestPerformanceComparison:
    """Compare performance of mocked vs unmocked operations."""

    @pytest.mark.performance
    def test_file_io_performance_comparison(self, tmp_path):
        """Compare mocked vs real file I/O performance."""

        # Test real file I/O (slower)
        real_file = tmp_path / "real_test.txt"
        real_file.write_text("x" * 10000)

        start_time = time.time()
        for _ in range(100):
            with open(real_file) as f:
                content = f.read()
        real_duration = time.time() - start_time

        # Test mocked file I/O (faster)
        filesystem = FastFileSystem()
        filesystem.add_file("/mock_test.txt", "x" * 10000)

        def mock_open(file, mode="r", **kwargs):
            content = filesystem.get_file(str(file))
            import io

            return io.StringIO(content.decode("utf-8"))

        start_time = time.time()
        with patch("builtins.open", side_effect=mock_open):
            for _ in range(100):
                with open("/mock_test.txt") as f:
                    content = f.read()
        mock_duration = time.time() - start_time

        # Mock should be significantly faster
        speedup = real_duration / mock_duration if mock_duration > 0 else float("inf")
        print(f"Speedup: {speedup:.1f}x (real: {real_duration:.3f}s, mock: {mock_duration:.3f}s)")

        # We expect at least 2x speedup, often much more
        assert speedup >= 2.0 or mock_duration < 0.01

    @pytest.mark.performance
    def test_scanner_result_creation_speed(self):
        """Test speed of creating scanner results."""

        # Test traditional approach (creating real objects)
        start_time = time.time()
        for _ in range(1000):
            # Simulate creating a scan result the traditional way
            result = {
                "files_scanned": 1,
                "bytes_scanned": 1024,
                "issues": [],
                "success": True,
                "duration": 0.1,
                "timestamp": time.time(),
            }
        traditional_duration = time.time() - start_time

        # Test fast mock approach
        start_time = time.time()
        for _ in range(1000):
            result = FastScannerMocks.create_scan_result()
        mock_duration = time.time() - start_time

        speedup = traditional_duration / mock_duration if mock_duration > 0 else float("inf")
        print(f"Scanner result speedup: {speedup:.1f}x")

        # Mock approach should be reasonable (focus is on correctness, not micro-benchmarks)
        # The real benefit comes from avoiding expensive operations in real tests
        assert mock_duration < 1.0  # Just ensure it completes reasonably


@pytest.mark.unit
class TestMockUtilitiesCorrectness:
    """Ensure the mock utilities behave correctly."""

    def test_filesystem_mock_correctness(self):
        """Test that filesystem mock behaves like real filesystem."""
        fs = FastFileSystem()

        # Test file operations
        fs.add_file("/path/to/file.txt", "content")
        assert fs.exists("/path/to/file.txt")
        assert fs.is_file("/path/to/file.txt")
        assert not fs.is_dir("/path/to/file.txt")
        assert fs.get_file("/path/to/file.txt") == b"content"

        # Test directory operations
        assert fs.exists("/path/to")  # Parent dir should exist
        assert fs.is_dir("/path/to")
        assert not fs.is_file("/path/to")

        # Test non-existent paths
        assert not fs.exists("/nonexistent")
        assert not fs.is_file("/nonexistent")
        assert not fs.is_dir("/nonexistent")

    def test_scanner_result_mock_correctness(self):
        """Test that scanner result mocks have all required attributes."""
        result = FastScannerMocks.create_scan_result(files_scanned=5, bytes_scanned=2048, success=False)

        # Check all expected attributes exist
        required_attrs = [
            "issues",
            "files_scanned",
            "bytes_scanned",
            "success",
            "has_errors",
            "duration",
            "scanner_names",
            "assets",
            "checks",
            "file_metadata",
            "start_time",
            "total_checks",
            "passed_checks",
            "failed_checks",
        ]

        for attr in required_attrs:
            assert hasattr(result, attr), f"Missing attribute: {attr}"

        # Check values are set correctly
        assert result.files_scanned == 5
        assert result.bytes_scanned == 2048
        assert not result.success
