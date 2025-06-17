"""
Tests for security enhancements in Joblib and NumPy scanners.
"""

import zlib

import numpy as np

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.joblib_scanner import JoblibScanner
from modelaudit.scanners.numpy_scanner import NumPyScanner


class TestJoblibScannerSecurity:
    """Test security enhancements for Joblib scanner."""

    def test_compression_bomb_detection(self, tmp_path):
        """Test that compression bombs are detected."""
        # Create a compression bomb (large data that compresses well)
        bomb_data = b"A" * (10 * 1024 * 1024)  # 10MB of 'A's
        compressed = zlib.compress(bomb_data, level=9)

        # Write to a .joblib file
        joblib_file = tmp_path / "bomb.joblib"
        joblib_file.write_bytes(compressed)

        # Configure scanner with low compression ratio limit
        config = {"max_decompression_ratio": 50.0}  # Lower than actual ratio
        scanner = JoblibScanner(config)

        result = scanner.scan(str(joblib_file))

        # Should detect compression bomb
        assert result.success is False
        bomb_issues = [
            issue
            for issue in result.issues
            if "compression ratio" in issue.message.lower()
        ]
        assert len(bomb_issues) > 0
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in bomb_issues)

    def test_large_file_protection(self, tmp_path):
        """Test protection against reading very large files."""
        # Create a large file
        large_file = tmp_path / "large.joblib"
        large_data = b"X" * (200 * 1024 * 1024)  # 200MB
        large_file.write_bytes(large_data)

        # Configure scanner with low file size limit
        config = {"max_file_read_size": 100 * 1024 * 1024}  # 100MB limit
        scanner = JoblibScanner(config)

        result = scanner.scan(str(large_file))

        # Should reject the large file
        assert result.success is False
        size_issues = [
            issue for issue in result.issues if "too large" in issue.message.lower()
        ]
        assert len(size_issues) > 0

    def test_decompressed_size_limit(self, tmp_path):
        """Test limit on decompressed size."""
        # Create data that will exceed decompressed size limit but has reasonable compression ratio
        large_data = b"B" * (200 * 1024 * 1024)  # 200MB
        compressed = zlib.compress(large_data)

        joblib_file = tmp_path / "large_decompressed.joblib"
        joblib_file.write_bytes(compressed)

        # Configure with high compression ratio limit but low decompressed size limit
        config = {
            "max_decompressed_size": 100 * 1024 * 1024,  # 100MB limit
            "max_decompression_ratio": 10000.0,  # Allow high compression ratio to test size limit
        }
        scanner = JoblibScanner(config)

        result = scanner.scan(str(joblib_file))

        assert result.success is False
        # Should be caught by either decompressed size limit or compression ratio
        security_issues = [
            issue
            for issue in result.issues
            if (
                "decompressed size too large" in issue.message.lower()
                or "compression ratio" in issue.message.lower()
            )
        ]
        assert len(security_issues) > 0

    def test_valid_compressed_joblib(self, tmp_path):
        """Test that valid compressed joblib files still work."""
        # Create reasonable compressed data
        data = {"test": "data", "numbers": list(range(100))}
        import pickle

        pickled = pickle.dumps(data)
        compressed = zlib.compress(pickled)

        joblib_file = tmp_path / "valid.joblib"
        joblib_file.write_bytes(compressed)

        scanner = JoblibScanner()
        result = scanner.scan(str(joblib_file))

        # Should succeed
        assert result.success is True


class TestNumPyScannerSecurity:
    """Test security enhancements for NumPy scanner."""

    def test_negative_dimension_rejection(self, tmp_path):
        """Test rejection of arrays with negative dimensions."""
        # We'll need to create a malformed numpy file manually
        # since numpy.save() won't create invalid files

        npy_file = tmp_path / "negative_dims.npy"

        # Create numpy file header manually with negative dimension
        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            header = "{'descr': '<f8', 'fortran_order': False, 'shape': (-10, 20), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add some dummy data
            f.write(b"\x00" * 1600)  # 20 * 8 bytes per float64

        scanner = NumPyScanner()
        result = scanner.scan(str(npy_file))

        assert result.success is False
        validation_issues = [
            issue
            for issue in result.issues
            if "negative dimension" in issue.message.lower()
        ]
        assert len(validation_issues) > 0

    def test_too_many_dimensions_rejection(self, tmp_path):
        """Test rejection of arrays with too many dimensions."""
        config = {"max_dimensions": 5}  # Low limit for testing
        scanner = NumPyScanner(config)

        # Create array with many dimensions
        shape = (2,) * 10  # 10 dimensions
        arr = np.zeros(shape)

        npy_file = tmp_path / "many_dims.npy"
        np.save(npy_file, arr)

        result = scanner.scan(str(npy_file))

        assert result.success is False
        dim_issues = [
            issue
            for issue in result.issues
            if "too many dimensions" in issue.message.lower()
        ]
        assert len(dim_issues) > 0

    def test_dimension_size_limit(self, tmp_path):
        """Test rejection of arrays with individual dimensions too large."""
        config = {"max_dimension_size": 1000}  # Low limit for testing
        scanner = NumPyScanner(config)

        # This would normally fail to create due to memory, but we'll
        # create the header manually
        npy_file = tmp_path / "large_dim.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            header = "{'descr': '<f8', 'fortran_order': False, 'shape': (2000,), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add minimal data (won't match expected size, but that's secondary)
            f.write(b"\x00" * 100)

        result = scanner.scan(str(npy_file))

        assert result.success is False
        size_issues = [
            issue for issue in result.issues if "too large" in issue.message.lower()
        ]
        assert len(size_issues) > 0

    def test_dangerous_dtype_rejection(self, tmp_path):
        """Test rejection of dangerous data types."""
        scanner = NumPyScanner()

        # Create numpy file with object dtype manually
        npy_file = tmp_path / "object_dtype.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            header = "{'descr': '|O', 'fortran_order': False, 'shape': (10,), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add some dummy data
            f.write(b"\x00" * 80)  # 10 * 8 bytes per object pointer

        result = scanner.scan(str(npy_file))

        assert result.success is False
        dtype_issues = [
            issue
            for issue in result.issues
            if "dangerous dtype" in issue.message.lower()
        ]
        assert len(dtype_issues) > 0

    def test_array_size_overflow_protection(self, tmp_path):
        """Test protection against integer overflow in size calculation."""
        config = {"max_array_bytes": 1024 * 1024}  # 1MB limit for testing
        scanner = NumPyScanner(config)

        # Create array dimensions that would overflow or exceed memory limit
        # Use dimensions that individually look reasonable but multiply to huge
        npy_file = tmp_path / "overflow.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            # Shape that multiplies to > 1MB with float64 (8 bytes each)
            header = "{'descr': '<f8', 'fortran_order': False, 'shape': (1000, 1000), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add minimal data
            f.write(b"\x00" * 100)

        result = scanner.scan(str(npy_file))

        assert result.success is False
        size_issues = [
            issue
            for issue in result.issues
            if "array too large" in issue.message.lower()
        ]
        assert len(size_issues) > 0

    def test_valid_numpy_array_still_works(self, tmp_path):
        """Test that valid numpy arrays still scan successfully."""
        # Create a normal, reasonable numpy array
        arr = np.array([[1, 2, 3], [4, 5, 6]], dtype=np.float32)

        npy_file = tmp_path / "valid.npy"
        np.save(npy_file, arr)

        scanner = NumPyScanner()
        result = scanner.scan(str(npy_file))

        # Should succeed
        assert result.success is True
        assert result.bytes_scanned > 0
        assert "shape" in result.metadata
        assert "dtype" in result.metadata


class TestConfigurableLimits:
    """Test that security limits are properly configurable."""

    def test_joblib_custom_limits(self, tmp_path):
        """Test that joblib limits can be customized."""
        config = {
            "max_decompression_ratio": 10.0,  # Very strict
            "max_decompressed_size": 1024,  # Very small
            "max_file_read_size": 2048,  # Very small
        }

        scanner = JoblibScanner(config)

        # Verify limits are set
        assert scanner.max_decompression_ratio == 10.0
        assert scanner.max_decompressed_size == 1024
        assert scanner.max_file_read_size == 2048

    def test_numpy_custom_limits(self, tmp_path):
        """Test that numpy limits can be customized."""
        config = {
            "max_array_bytes": 1000,
            "max_dimensions": 3,
            "max_dimension_size": 100,
            "max_itemsize": 16,
        }

        scanner = NumPyScanner(config)

        # Verify limits are set
        assert scanner.max_array_bytes == 1000
        assert scanner.max_dimensions == 3
        assert scanner.max_dimension_size == 100
        assert scanner.max_itemsize == 16
