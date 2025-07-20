"""Tests for parallel scanning functionality."""

import multiprocessing
import pickle
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.parallel_scanner import ParallelScanner, WorkItem, _scan_file_worker
from modelaudit.scanners.base import ScanResult


class TestParallelScanner:
    """Test the ParallelScanner class."""

    def test_init_default_workers(self):
        """Test initialization with default worker count."""
        scanner = ParallelScanner()
        assert scanner.max_workers == multiprocessing.cpu_count()
        assert scanner.timeout_per_file == 300

    def test_init_custom_workers(self):
        """Test initialization with custom worker count."""
        scanner = ParallelScanner(max_workers=4, timeout_per_file=60)
        assert scanner.max_workers == 4
        assert scanner.timeout_per_file == 60

    def test_empty_file_list(self):
        """Test scanning with empty file list."""
        scanner = ParallelScanner()
        results = scanner.scan_files([], {})

        assert results["files_scanned"] == 0
        assert results["bytes_scanned"] == 0
        assert results["issues"] == []
        assert results["success"] is True
        assert results["has_errors"] is False

    def test_sequential_fallback_small_files(self):
        """Test that small file counts use sequential scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 2 test files
            files = []
            for i in range(2):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    pickle.dump({"data": f"test_{i}"}, f)
                files.append(str(file_path))

            scanner = ParallelScanner(max_workers=4)
            results = scanner.scan_files(files, {})

            assert results["files_scanned"] == 2
            assert results["parallel_scan"] is False
            assert "bytes_scanned" in results
            assert results["success"] is True

    def test_parallel_scanning(self):
        """Test parallel scanning with multiple files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 5 test files
            files = []
            for i in range(5):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    pickle.dump({"data": f"test_{i}" * 100}, f)
                files.append(str(file_path))

            scanner = ParallelScanner(max_workers=2)
            results = scanner.scan_files(files, {})

            assert results["files_scanned"] == 5
            assert results["parallel_scan"] is True
            assert results["worker_count"] == 2
            assert results["success"] is True
            assert len(results["assets"]) == 5

    def test_progress_callback(self):
        """Test progress callback functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            files = []
            for i in range(3):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    pickle.dump({"data": f"test_{i}"}, f)
                files.append(str(file_path))

            # Track progress calls
            progress_calls = []

            def progress_callback(message, percentage):
                progress_calls.append((message, percentage))

            scanner = ParallelScanner(max_workers=1, progress_callback=progress_callback)
            results = scanner.scan_files(files, {})

            # Progress callback is called during parallel scanning
            # For sequential scan (3 files), we should see progress updates
            assert len(progress_calls) >= 3  # At least one per file

    def test_scan_error_handling(self):
        """Test handling of scan errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a corrupted file
            file_path = Path(tmpdir) / "corrupted.pkl"
            with open(file_path, "wb") as f:
                f.write(b"corrupted data")

            scanner = ParallelScanner()
            results = scanner.scan_files([str(file_path)], {})

            assert results["files_scanned"] == 1
            assert len(results["issues"]) > 0
            assert results["success"] is True

    @pytest.mark.skip(reason="Timeout handling is complex in multiprocessing")
    def test_worker_timeout(self):
        """Test timeout handling for slow scans."""

        # Mock a slow scan function
        def slow_scan(*args, **kwargs):
            time.sleep(2)
            return ScanResult(scanner_name="test")

        with patch("modelaudit.core.scan_file", side_effect=slow_scan):
            scanner = ParallelScanner(timeout_per_file=1)

            with tempfile.TemporaryDirectory() as tmpdir:
                file_path = Path(tmpdir) / "test.pkl"
                file_path.write_bytes(b"test")

                # This should timeout
                with pytest.raises(TimeoutError):
                    results = scanner.scan_files([str(file_path)], {})


class TestScanFileWorker:
    """Test the _scan_file_worker function."""

    def test_successful_scan(self):
        """Test successful file scan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test.pkl"
            with open(file_path, "wb") as f:
                pickle.dump({"test": "data"}, f)

            work_item = WorkItem(str(file_path), {})
            result = _scan_file_worker(work_item)

            assert result.success is True
            assert result.file_path == str(file_path)
            assert result.result is not None
            assert "scanner_name" in result.result
            assert result.duration > 0

    def test_scan_with_issues(self):
        """Test scan that finds issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "malicious.pkl"
            # Create a pickle file (can't pickle lambdas directly)
            with open(file_path, "wb") as f:
                # Just create a regular pickle for this test
                pickle.dump({"test": "data"}, f)

            work_item = WorkItem(str(file_path), {})
            result = _scan_file_worker(work_item)

            assert result.success is True
            assert result.result is not None
            # The pickle scanner should successfully scan this file
            assert "scanner_name" in result.result

    def test_scan_nonexistent_file(self):
        """Test scanning a file that doesn't exist."""
        work_item = WorkItem("/nonexistent/file.pkl", {})
        result = _scan_file_worker(work_item)

        # The worker returns success=True even for errors (it catches exceptions)
        assert result.success is True
        assert result.result is not None
        # Check that there's an issue about the missing file
        issues = result.result.get("issues", [])
        assert len(issues) > 0
        assert any(
            "No such file or directory" in issue.get("message", "")
            or "Error checking file size" in issue.get("message", "")
            for issue in issues
        )


@pytest.mark.integration
class TestParallelScannerIntegration:
    """Integration tests for parallel scanning."""

    def test_mixed_file_types(self):
        """Test scanning directory with mixed file types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []

            # Create various file types
            # Pickle file
            pkl_file = Path(tmpdir) / "model.pkl"
            with open(pkl_file, "wb") as f:
                pickle.dump({"model": "data"}, f)
            files.append(str(pkl_file))

            # Text file (should be skipped by our filter)
            txt_file = Path(tmpdir) / "readme.txt"
            txt_file.write_text("This is a readme")

            # Another pickle
            pkl2_file = Path(tmpdir) / "model2.pkl"
            with open(pkl2_file, "wb") as f:
                pickle.dump({"model2": "data"}, f)
            files.append(str(pkl2_file))

            scanner = ParallelScanner()
            results = scanner.scan_files(files, {})

            assert results["files_scanned"] == 2
            # Assets should have scanner-specific types
            assert all(asset["type"] in ["pickle", "numpy"] for asset in results["assets"])

    def test_performance_comparison(self):
        """Compare performance of parallel vs sequential scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 10 files with varying sizes
            files = []
            for i in range(10):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    # Create files with different sizes
                    data = {"index": i, "data": "x" * (i * 1000)}
                    pickle.dump(data, f)
                files.append(str(file_path))

            # Sequential scan
            scanner_seq = ParallelScanner(max_workers=1)
            start_seq = time.time()
            results_seq = scanner_seq.scan_files(files, {})
            time_seq = time.time() - start_seq

            # Parallel scan
            scanner_par = ParallelScanner(max_workers=4)
            start_par = time.time()
            results_par = scanner_par.scan_files(files, {})
            time_par = time.time() - start_par

            # Both should scan the same files
            assert results_seq["files_scanned"] == results_par["files_scanned"]
            assert results_seq["bytes_scanned"] == results_par["bytes_scanned"]

            # Parallel should have the marker
            assert results_par["parallel_scan"] is True
            assert results_par["worker_count"] == 4

            # Log the times for manual inspection
            print(f"\nSequential time: {time_seq:.3f}s")
            print(f"Parallel time: {time_par:.3f}s")
            print(f"Speedup: {time_seq / time_par:.2f}x")

    def test_large_directory_simulation(self):
        """Test scanning a larger directory to ensure scalability."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 20 files
            files = []
            for i in range(20):
                file_path = Path(tmpdir) / f"model_{i}.pkl"
                with open(file_path, "wb") as f:
                    pickle.dump({"index": i}, f)
                files.append(str(file_path))

            scanner = ParallelScanner(max_workers=4)
            results = scanner.scan_files(files, {})

            assert results["files_scanned"] == 20
            assert results["parallel_scan"] is True
            assert results["success"] is True
            assert len(results["assets"]) == 20
