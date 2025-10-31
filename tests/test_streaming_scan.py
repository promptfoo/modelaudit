"""Tests for streaming scan-and-delete functionality."""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from modelaudit.core import scan_model_streaming
from modelaudit.scanners.base import ScanResult
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash


@pytest.fixture
def temp_test_files():
    """Create temporary test files for streaming."""
    files = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write(f"Test content {i}")
            files.append(Path(tmp.name))
    yield files
    # Cleanup
    for file_path in files:
        if file_path.exists():
            file_path.unlink()


def create_mock_scan_result(bytes_scanned: int = 1024) -> ScanResult:
    """Create a mock ScanResult for testing."""
    result = ScanResult(scanner_name="test_scanner")
    result.bytes_scanned = bytes_scanned
    result.success = True
    return result


def test_scan_model_streaming_basic(temp_test_files):
    """Test basic streaming scan functionality."""

    def file_generator():
        """Generator that yields (path, is_last) tuples."""
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # Mock scan_file to return scan results
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for f in temp_test_files]

        # Run streaming scan (don't delete for this test)
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Verify results
        assert result.bytes_scanned == 300  # 3 files * 100 bytes
        assert result.files_scanned == 3
        assert result.has_errors is False
        assert result.content_hash is not None
        assert len(result.content_hash) == 64  # SHA256 hex string


def test_scan_model_streaming_with_deletion(temp_test_files):
    """Test that files are deleted after scanning in streaming mode."""

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result(bytes_scanned=100) for f in temp_test_files]

        # Verify files exist before scan
        for f in temp_test_files:
            assert f.exists()

        # Run streaming scan with deletion
        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=True,
        )

        # Verify files were deleted
        for f in temp_test_files:
            assert not f.exists()

        # Verify scan completed
        assert result.files_scanned == 3
        assert result.content_hash is not None


def test_scan_model_streaming_content_hash_deterministic():
    """Test that content hash is deterministic for same files."""
    # Create two files with same content
    files1 = []
    files2 = []

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files1.append(Path(tmp.name))

    for _i in range(2):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("Same content")
            files2.append(Path(tmp.name))

    try:

        def gen1():
            for i, f in enumerate(files1):
                yield (f, i == len(files1) - 1)

        def gen2():
            for i, f in enumerate(files2):
                yield (f, i == len(files2) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            mock_scan.side_effect = [create_mock_scan_result() for _ in files1 + files2]

            result1 = scan_model_streaming(file_generator=gen1(), timeout=30, delete_after_scan=False)
            result2 = scan_model_streaming(file_generator=gen2(), timeout=30, delete_after_scan=False)

            # Same content should produce same hash
            assert result1.content_hash == result2.content_hash

    finally:
        for file_path in files1 + files2:
            if file_path.exists():
                file_path.unlink()


def test_scan_model_streaming_empty_generator():
    """Test streaming scan with empty file generator."""

    def empty_generator():
        return
        yield  # Make it a generator

    result = scan_model_streaming(
        file_generator=empty_generator(),
        timeout=30,
        delete_after_scan=True,
    )

    # Should complete without errors but with no results
    assert result.files_scanned == 0
    assert result.bytes_scanned == 0
    assert result.content_hash is None or result.content_hash == compute_aggregate_hash([])


def test_scan_model_streaming_scan_error_handling(temp_test_files):
    """Test that scan errors are handled gracefully in streaming mode."""

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            is_last = i == len(temp_test_files) - 1
            yield (file_path, is_last)

    with patch("modelaudit.core.scan_file") as mock_scan:
        # First file succeeds, second fails, third succeeds
        mock_scan.side_effect = [
            create_mock_scan_result(),
            Exception("Scan failed"),
            create_mock_scan_result(),
        ]

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # Should have errors flag set
        assert result.has_errors is True
        # Should have scanned 2 files (1st and 3rd)
        assert result.files_scanned == 2


def test_scan_model_streaming_timeout():
    """Test that timeout is respected in streaming mode."""
    # Create multiple files to trigger timeout between scans
    temp_files = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(f"Test {i}")
            temp_files.append(Path(f.name))

    try:

        def slow_generator():
            for i, f in enumerate(temp_files):
                yield (f, i == len(temp_files) - 1)

        with patch("modelaudit.core.scan_file") as mock_scan:
            # Make each scan take 0.5 seconds (3 files = 1.5s total)
            def slow_scan(*args, **kwargs):
                time.sleep(0.5)
                return create_mock_scan_result()

            mock_scan.side_effect = slow_scan

            # Set timeout to 1 second (should complete 1-2 files, then timeout)
            result = scan_model_streaming(
                file_generator=slow_generator(),
                timeout=1,  # 1 second timeout
                delete_after_scan=False,
            )

            # Should timeout and have errors
            assert result.has_errors is True
            # Should have scanned at least 1 file but not all 3
            assert 1 <= result.files_scanned < 3

    finally:
        for file_path in temp_files:
            if file_path.exists():
                file_path.unlink()


def test_compute_aggregate_hash_empty_list():
    """Test aggregate hash computation with empty list."""
    result = compute_aggregate_hash([])
    # Should return hash of empty string
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result == expected


def test_compute_aggregate_hash_single_hash():
    """Test aggregate hash computation with single hash."""
    file_hash = "a" * 64  # Mock SHA256 hash
    result = compute_aggregate_hash([file_hash])
    assert len(result) == 64
    assert result != file_hash  # Should be different (hash of hash)


def test_compute_aggregate_hash_multiple_hashes():
    """Test aggregate hash computation with multiple hashes."""
    hashes = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
    ]
    result = compute_aggregate_hash(hashes)
    assert len(result) == 64


def test_compute_aggregate_hash_order_independence():
    """Test that aggregate hash is order-independent (sorted)."""
    hashes = ["aaa", "bbb", "ccc"]
    reversed_hashes = ["ccc", "bbb", "aaa"]

    result1 = compute_aggregate_hash(hashes)
    result2 = compute_aggregate_hash(reversed_hashes)

    # Should be the same (sorted internally)
    assert result1 == result2


def test_scan_model_streaming_progress_callback(temp_test_files):
    """Test that progress callback is called during streaming scan."""
    progress_calls = []

    def progress_callback(message, percentage):
        progress_calls.append((message, percentage))

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with patch("modelaudit.core.scan_file") as mock_scan:
        mock_scan.side_effect = [create_mock_scan_result() for f in temp_test_files]

        scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            progress_callback=progress_callback,
            delete_after_scan=False,
        )

        # Should have received progress updates
        assert len(progress_calls) > 0
        # Should have both hashing and scanning messages
        messages = [msg for msg, _ in progress_calls]
        assert any("Hashing" in msg for msg in messages)
        assert any("Scanning" in msg for msg in messages)


def test_scan_model_streaming_asset_creation(temp_test_files):
    """Test that assets are created during streaming scan."""

    def file_generator():
        for i, file_path in enumerate(temp_test_files):
            yield (file_path, i == len(temp_test_files) - 1)

    with (
        patch("modelaudit.core.scan_file") as mock_scan,
        patch("modelaudit.utils.helpers.assets.asset_from_scan_result") as mock_asset,
    ):
        mock_scan.side_effect = [create_mock_scan_result() for f in temp_test_files]

        # Mock asset creation
        mock_asset.return_value = {
            "path": "test",
            "type": "test",
            "size": 100,
        }

        result = scan_model_streaming(
            file_generator=file_generator(),
            timeout=30,
            delete_after_scan=False,
        )

        # asset_from_scan_result should be called for each file
        assert mock_asset.call_count == 3
