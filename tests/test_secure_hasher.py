"""Tests for secure file hashing functionality."""

import builtins
import contextlib

import pytest

from modelaudit.utils.secure_hasher import (
    SecureFileHasher,
    benchmark_hashing_performance,
    hash_file_secure,
    verify_file_hash,
)


class TestSecureFileHasher:
    """Test cases for SecureFileHasher class."""

    def test_init_default_threshold(self):
        """Test hasher initialization with default threshold."""
        hasher = SecureFileHasher()
        assert hasher.full_hash_threshold == 2 * 1024**3  # 2GB
        assert hasher.chunk_size == 8 * 1024 * 1024  # 8MB

    def test_init_custom_threshold(self):
        """Test hasher initialization with custom threshold."""
        threshold = 100 * 1024 * 1024  # 100MB
        hasher = SecureFileHasher(threshold)
        assert hasher.full_hash_threshold == threshold

    def test_hash_small_file_secure_method(self, tmp_path):
        """Test hashing of small files uses secure method."""
        # Create test file < 2GB
        test_file = tmp_path / "small_test.bin"
        test_content = b"Hello, ModelAudit!" * 1000  # ~18KB
        test_file.write_bytes(test_content)

        hasher = SecureFileHasher()
        result = hasher.hash_file(str(test_file))

        # Should use secure method for small files
        assert result.startswith("secure:")
        assert len(result.split(":")[1]) == 64  # Blake2b 256-bit = 64 hex chars

    def test_hash_large_file_fingerprint_method(self, tmp_path):
        """Test hashing of large files uses fingerprint method."""
        # Create test file > 2GB threshold by setting low threshold
        test_file = tmp_path / "large_test.bin"
        test_content = b"A" * 1024 * 1024  # 1MB
        test_file.write_bytes(test_content)

        # Use hasher with very low threshold to trigger fingerprint method
        hasher = SecureFileHasher(full_hash_threshold=512 * 1024)  # 512KB threshold
        result = hasher.hash_file(str(test_file))

        # Should use fingerprint method for "large" files
        assert result.startswith("fingerprint:")
        assert len(result.split(":")[1]) == 64  # Blake2b 256-bit = 64 hex chars

    def test_hash_nonexistent_file(self):
        """Test hashing nonexistent file raises ValueError."""
        hasher = SecureFileHasher()

        with pytest.raises(ValueError, match="File does not exist"):
            hasher.hash_file("/nonexistent/file.bin")

    def test_hash_empty_file(self, tmp_path):
        """Test hashing empty file raises ValueError."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        hasher = SecureFileHasher()

        with pytest.raises(ValueError, match="File is empty"):
            hasher.hash_file(str(empty_file))

    def test_hash_consistency(self, tmp_path):
        """Test that identical files produce identical hashes."""
        # Create two identical files
        content = b"Test content for consistency check" * 1000

        file1 = tmp_path / "file1.bin"
        file2 = tmp_path / "file2.bin"

        file1.write_bytes(content)
        file2.write_bytes(content)

        hasher = SecureFileHasher()
        hash1 = hasher.hash_file(str(file1))
        hash2 = hasher.hash_file(str(file2))

        assert hash1 == hash2

    def test_hash_different_content(self, tmp_path):
        """Test that different files produce different hashes."""
        file1 = tmp_path / "file1.bin"
        file2 = tmp_path / "file2.bin"

        file1.write_bytes(b"Content A" * 1000)
        file2.write_bytes(b"Content B" * 1000)

        hasher = SecureFileHasher()
        hash1 = hasher.hash_file(str(file1))
        hash2 = hasher.hash_file(str(file2))

        assert hash1 != hash2

    def test_verify_hash_success(self, tmp_path):
        """Test successful hash verification."""
        test_file = tmp_path / "verify_test.bin"
        test_content = b"Verification test content"
        test_file.write_bytes(test_content)

        hasher = SecureFileHasher()
        file_hash = hasher.hash_file(str(test_file))

        # Verification should succeed
        assert hasher.verify_hash(str(test_file), file_hash) is True

    def test_verify_hash_failure(self, tmp_path):
        """Test hash verification failure."""
        test_file = tmp_path / "verify_test.bin"
        test_content = b"Original content"
        test_file.write_bytes(test_content)

        hasher = SecureFileHasher()
        original_hash = hasher.hash_file(str(test_file))

        # Modify file
        test_file.write_bytes(b"Modified content")

        # Verification should fail
        assert hasher.verify_hash(str(test_file), original_hash) is False

    def test_get_hash_info_secure(self):
        """Test parsing secure hash info."""
        hasher = SecureFileHasher()
        hash_string = "secure:abcd1234ef567890"

        info = hasher.get_hash_info(hash_string)

        assert info["method"] == "full_hash"
        assert info["algorithm"] == "blake2b"
        assert info["security_level"] == "high"
        assert info["hash"] == "abcd1234ef567890"

    def test_get_hash_info_fingerprint(self):
        """Test parsing fingerprint hash info."""
        hasher = SecureFileHasher()
        hash_string = "fingerprint:1234abcd5678ef90"

        info = hasher.get_hash_info(hash_string)

        assert info["method"] == "enhanced_fingerprint"
        assert info["algorithm"] == "blake2b"
        assert info["security_level"] == "medium"
        assert info["hash"] == "1234abcd5678ef90"

    def test_get_hash_info_unknown(self):
        """Test parsing unknown hash format."""
        hasher = SecureFileHasher()
        hash_string = "unknown_format:hash_value"

        info = hasher.get_hash_info(hash_string)

        assert info["method"] == "unknown"
        assert info["algorithm"] == "unknown"
        assert info["security_level"] == "unknown"
        assert info["hash"] == "unknown_format:hash_value"


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_hash_file_secure_function(self, tmp_path):
        """Test hash_file_secure convenience function."""
        test_file = tmp_path / "convenience_test.bin"
        test_file.write_bytes(b"Test content for convenience function")

        result = hash_file_secure(str(test_file))

        assert result.startswith("secure:")
        assert len(result.split(":")[1]) == 64

    def test_hash_file_secure_with_threshold(self, tmp_path):
        """Test hash_file_secure with custom threshold."""
        test_file = tmp_path / "threshold_test.bin"
        test_content = b"A" * 1024  # 1KB
        test_file.write_bytes(test_content)

        # Set very low threshold to force fingerprint method
        result = hash_file_secure(str(test_file), threshold=512)

        assert result.startswith("fingerprint:")

    def test_verify_file_hash_function(self, tmp_path):
        """Test verify_file_hash convenience function."""
        test_file = tmp_path / "verify_convenience_test.bin"
        test_file.write_bytes(b"Content for verification test")

        # Get hash
        file_hash = hash_file_secure(str(test_file))

        # Verification should succeed
        assert verify_file_hash(str(test_file), file_hash) is True

        # Modify file
        test_file.write_bytes(b"Modified content")

        # Verification should fail
        assert verify_file_hash(str(test_file), file_hash) is False


class TestBenchmarking:
    """Test benchmarking functionality."""

    def test_benchmark_hashing_performance(self, tmp_path):
        """Test benchmarking function."""
        # Create test file
        test_file = tmp_path / "benchmark_test.bin"
        test_content = b"Benchmark content " * 1000  # ~17KB
        test_file.write_bytes(test_content)

        # Run benchmark
        results = benchmark_hashing_performance(str(test_file), iterations=2)

        # Verify results structure
        assert "file_size_mb" in results
        assert "avg_time_seconds" in results
        assert "min_time_seconds" in results
        assert "max_time_seconds" in results
        assert "throughput_mbps" in results
        assert "hash_method" in results
        assert "hash_result" in results

        # Verify reasonable values
        assert results["file_size_mb"] > 0
        assert results["avg_time_seconds"] > 0
        assert results["throughput_mbps"] > 0
        assert results["hash_method"] in ["full_hash", "enhanced_fingerprint"]
        assert results["hash_result"].startswith(("secure:", "fingerprint:"))

    def test_benchmark_nonexistent_file(self):
        """Test benchmarking with nonexistent file."""
        with pytest.raises(ValueError, match="Test file does not exist"):
            benchmark_hashing_performance("/nonexistent/file.bin")


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_hash_permission_denied(self, tmp_path):
        """Test handling of permission denied errors."""
        # This test is platform-specific and may not work on all systems
        test_file = tmp_path / "permission_test.bin"
        test_file.write_bytes(b"Test content")

        # Try to make file unreadable (may not work on all systems)
        try:
            test_file.chmod(0o000)

            hasher = SecureFileHasher()
            with pytest.raises(OSError):
                hasher.hash_file(str(test_file))

        finally:
            # Restore permissions for cleanup
            with contextlib.suppress(builtins.BaseException):
                test_file.chmod(0o644)


# Integration test with actual pickle file
def test_integration_with_pickle_file(tmp_path):
    """Test integration with a real pickle file."""
    import pickle

    # Create a simple pickle file
    test_data = {"model": "test", "weights": [1, 2, 3, 4, 5]}
    pickle_file = tmp_path / "test_model.pkl"

    with open(pickle_file, "wb") as f:
        pickle.dump(test_data, f)

    # Hash the pickle file
    hasher = SecureFileHasher()
    result = hasher.hash_file(str(pickle_file))

    # Verify result format
    assert result.startswith("secure:")
    assert len(result.split(":")[1]) == 64

    # Verify consistency
    result2 = hasher.hash_file(str(pickle_file))
    assert result == result2

    # Verify verification works
    assert hasher.verify_hash(str(pickle_file), result) is True
