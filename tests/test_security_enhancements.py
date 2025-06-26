"""
Tests for security enhancements in Joblib and NumPy scanners.
"""

import lzma
import pickle
import zipfile
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
        bomb_issues = [issue for issue in result.issues if "compression ratio" in issue.message.lower()]
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
        size_issues = [issue for issue in result.issues if "too large" in issue.message.lower()]
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
            if ("decompressed size too large" in issue.message.lower() or "compression ratio" in issue.message.lower())
        ]
        assert len(security_issues) > 0

    def test_valid_compressed_joblib(self, tmp_path):
        """Test that valid compressed joblib files still work."""
        # Create reasonable compressed data
        data = {"test": "data", "numbers": list(range(100))}
        pickled = pickle.dumps(data)
        compressed = zlib.compress(pickled)

        joblib_file = tmp_path / "valid.joblib"
        joblib_file.write_bytes(compressed)

        scanner = JoblibScanner()
        result = scanner.scan(str(joblib_file))

        # Should succeed
        assert result.success is True

    def test_can_handle_edge_cases(self, tmp_path):
        """Test can_handle method with various edge cases."""
        scanner = JoblibScanner()

        # Test with directory
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()
        assert scanner.can_handle(str(test_dir)) is False

        # Test with wrong extension
        wrong_ext = tmp_path / "test.pkl"
        wrong_ext.write_text("test")
        assert scanner.can_handle(str(wrong_ext)) is False

        # Test with correct extension
        correct_ext = tmp_path / "test.joblib"
        correct_ext.write_text("test")
        assert scanner.can_handle(str(correct_ext)) is True

    def test_lzma_compressed_joblib(self, tmp_path):
        """Test LZMA compressed joblib files."""
        # Create LZMA compressed data
        data = {"test": "lzma_data", "values": [1, 2, 3, 4, 5]}
        pickled = pickle.dumps(data)
        compressed = lzma.compress(pickled)

        joblib_file = tmp_path / "lzma.joblib"
        joblib_file.write_bytes(compressed)

        scanner = JoblibScanner()
        result = scanner.scan(str(joblib_file))

        # Should succeed
        assert result.success is True

    def test_zip_format_joblib(self, tmp_path):
        """Test joblib files that are actually ZIP archives."""
        # Create a ZIP file with .joblib extension
        zip_file = tmp_path / "archive.joblib"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("test.txt", "test content")

        scanner = JoblibScanner()
        result = scanner.scan(str(zip_file))

        # Should delegate to ZIP scanner and succeed
        assert result.success is True

    def test_direct_pickle_joblib(self, tmp_path):
        """Test joblib files that are direct pickle (not compressed)."""
        # Create direct pickle data with pickle magic bytes
        data = {"test": "direct_pickle"}
        pickled = pickle.dumps(data, protocol=2)  # Protocol 2 starts with 0x80

        joblib_file = tmp_path / "direct.joblib"
        joblib_file.write_bytes(pickled)

        scanner = JoblibScanner()
        result = scanner.scan(str(joblib_file))

        # Should succeed
        assert result.success is True

    def test_invalid_compression_format(self, tmp_path):
        """Test handling of invalid/unrecognized compression formats."""
        # Create file with random bytes (not valid compression)
        invalid_data = b"This is not compressed data at all!"

        joblib_file = tmp_path / "invalid.joblib"
        joblib_file.write_bytes(invalid_data)

        scanner = JoblibScanner()
        result = scanner.scan(str(joblib_file))

        # Should fail with decompression error
        assert result.success is False
        decomp_issues = [issue for issue in result.issues if "unable to decompress" in issue.message.lower()]
        assert len(decomp_issues) > 0

    def test_file_read_chunk_limit(self, tmp_path):
        """Test chunked file reading with size check during read."""
        # Create a file that would pass initial size check but fail during chunked read
        # This is tricky since we check file size first, but let's test the chunked read logic

        # Test with a file exactly at the limit
        limit_data = b"X" * (50 * 1024 * 1024)  # 50MB
        limit_file = tmp_path / "at_limit.joblib"
        limit_file.write_bytes(limit_data)

        config = {"max_file_read_size": 50 * 1024 * 1024}  # Exactly 50MB limit
        scanner = JoblibScanner(config)

        # This should work (at the limit)
        result = scanner.scan(str(limit_file))
        # May fail on decompression but not on file read
        assert "File read exceeds limit" not in str(result.issues)


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
        validation_issues = [issue for issue in result.issues if "negative dimension" in issue.message.lower()]
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
        dim_issues = [issue for issue in result.issues if "too many dimensions" in issue.message.lower()]
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
        size_issues = [issue for issue in result.issues if "too large" in issue.message.lower()]
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
        dtype_issues = [issue for issue in result.issues if "dangerous dtype" in issue.message.lower()]
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
        size_issues = [issue for issue in result.issues if "array too large" in issue.message.lower()]
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

    def test_numpy_version_2_format(self, tmp_path):
        """Test NumPy format version 2.0 handling."""
        # Create array that will use version 2.0 format
        # Use a very long array description to trigger v2.0 format

        # Create a large 4D array that should trigger version 2.0
        # due to large header size, not structured dtype
        arr = np.zeros((100, 50, 20, 10), dtype=np.float64)

        npy_file = tmp_path / "version2.npy"
        np.save(npy_file, arr)

        # Allow structured arrays for this test
        config = {
            "max_array_bytes": 10 * 1024 * 1024 * 1024,
        }  # 10GB limit to allow large test array
        scanner = NumPyScanner(config)
        result = scanner.scan(str(npy_file))

        # Should succeed
        assert result.success is True

    def test_large_itemsize_rejection(self, tmp_path):
        """Test rejection of dtypes with very large item sizes."""
        config = {"max_itemsize": 100}  # Low limit for testing
        scanner = NumPyScanner(config)

        # Create numpy file with large itemsize manually
        npy_file = tmp_path / "large_itemsize.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            # String dtype with large size (200 bytes per string)
            header = "{'descr': '<U200', 'fortran_order': False, 'shape': (5,), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add minimal data
            f.write(b"\x00" * 100)

        result = scanner.scan(str(npy_file))

        assert result.success is False
        itemsize_issues = [issue for issue in result.issues if "itemsize too large" in issue.message.lower()]
        assert len(itemsize_issues) > 0

    def test_void_dtype_rejection(self, tmp_path):
        """Test rejection of void dtype."""
        scanner = NumPyScanner()

        # Create numpy file with void dtype manually
        npy_file = tmp_path / "void_dtype.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x01\x00")  # Version 1.0
            header = "{'descr': '|V10', 'fortran_order': False, 'shape': (5,), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add some dummy data
            f.write(b"\x00" * 50)  # 5 * 10 bytes per void

        result = scanner.scan(str(npy_file))

        assert result.success is False
        dtype_issues = [issue for issue in result.issues if "dangerous dtype" in issue.message.lower()]
        assert len(dtype_issues) > 0

    def test_unsupported_numpy_version(self, tmp_path):
        """Test handling of unsupported NumPy file versions."""
        scanner = NumPyScanner()

        # Create numpy file with unsupported version manually
        npy_file = tmp_path / "unsupported_version.npy"

        with open(npy_file, "wb") as f:
            f.write(b"\x93NUMPY")  # Magic
            f.write(b"\x03\x00")  # Version 3.0 (hypothetical future version)
            header = "{'descr': '<f8', 'fortran_order': False, 'shape': (10,), }"
            header_len = len(header)
            f.write(header_len.to_bytes(2, "little"))
            f.write(header.encode("latin1"))
            # Add some dummy data
            f.write(b"\x00" * 80)

        result = scanner.scan(str(npy_file))

        # Should either succeed (if NumPy handles it) or fail gracefully
        # The important thing is it doesn't crash
        assert result is not None


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
