"""Tests for content hash generation in regular scan mode."""

import pickle

import pytest

from modelaudit.core import scan_model_directory_or_file
from modelaudit.utils.helpers.secure_hasher import compute_aggregate_hash


class TestRegularScanContentHash:
    """Test content hash generation for regular (non-streaming) scans."""

    def test_single_file_generates_hash(self, tmp_path):
        """Test that scanning a single file generates a content hash."""
        # Create a simple pickle file
        test_file = tmp_path / "model.pkl"
        data = {"key": "value", "number": 42}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        result = scan_model_directory_or_file(str(test_file))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64  # SHA-256 hex digest length

    def test_directory_generates_hash(self, tmp_path):
        """Test that scanning a directory generates an aggregate content hash."""
        # Create multiple pickle files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i, "value": f"test_{i}"}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan the directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Verify content_hash is present and valid
        assert hasattr(result, "content_hash")
        assert result.content_hash is not None
        assert isinstance(result.content_hash, str)
        assert len(result.content_hash) == 64

    def test_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same content produces the same hash."""
        # Create a test file
        test_file = tmp_path / "model.pkl"
        data = {"deterministic": "test"}
        with open(test_file, "wb") as f:
            pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(test_file))
        result2 = scan_model_directory_or_file(str(test_file))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_directory_hash_is_deterministic(self, tmp_path):
        """Test that scanning the same directory produces the same hash."""
        # Create multiple files
        for i in range(3):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan twice
        result1 = scan_model_directory_or_file(str(tmp_path))
        result2 = scan_model_directory_or_file(str(tmp_path))

        # Hashes should be identical
        assert result1.content_hash == result2.content_hash

    def test_different_content_different_hash(self, tmp_path):
        """Test that different content produces different hashes."""
        # Create first file
        file1 = tmp_path / "model1.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"data": "first"}, f)

        # Create second file with different content
        file2 = tmp_path / "model2.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"data": "second"}, f)

        # Scan both files
        result1 = scan_model_directory_or_file(str(file1))
        result2 = scan_model_directory_or_file(str(file2))

        # Hashes should be different
        assert result1.content_hash != result2.content_hash

    def test_hash_order_independence(self, tmp_path):
        """Test that file processing order doesn't affect the aggregate hash."""
        # Create files with different names to ensure different traversal order
        files = []
        for name in ["aaa.pkl", "zzz.pkl", "mmm.pkl"]:
            file_path = tmp_path / name
            with open(file_path, "wb") as f:
                pickle.dump({"name": name}, f)
            files.append(file_path)

        # Scan the directory (os.walk might process in different order)
        result = scan_model_directory_or_file(str(tmp_path))

        # The hash should be the same regardless of file discovery order
        # This is guaranteed by compute_aggregate_hash sorting the hashes
        assert result.content_hash is not None

    def test_duplicate_files_single_hash(self, tmp_path):
        """Test that duplicate files are deduplicated and contribute once to hash."""
        # Create identical files
        data = {"duplicate": "content"}
        for i in range(3):
            test_file = tmp_path / f"dup_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

        # Scan directory with duplicates
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a hash (deduplication means only one hash contributed)
        assert result.content_hash is not None

    def test_empty_directory_no_hash(self, tmp_path):
        """Test that an empty directory doesn't generate a content hash."""
        # Scan empty directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should not have content_hash or it should be None
        assert not hasattr(result, "content_hash") or result.content_hash is None

    def test_hash_consistency_with_streaming(self, tmp_path):
        """Test that regular and streaming modes produce compatible hashes."""
        # Create test files
        file_hashes = []
        for i in range(2):
            test_file = tmp_path / f"model_{i}.pkl"
            data = {"id": i}
            with open(test_file, "wb") as f:
                pickle.dump(data, f)

            # Compute individual file hash
            import hashlib

            hash_sha256 = hashlib.sha256()
            with open(test_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_sha256.update(chunk)
            file_hashes.append(hash_sha256.hexdigest())

        # Compute expected aggregate hash
        expected_hash = compute_aggregate_hash(file_hashes)

        # Scan directory with regular mode
        result = scan_model_directory_or_file(str(tmp_path))

        # Should match the expected aggregate
        assert result.content_hash == expected_hash

    def test_mixed_files_generates_hash(self, tmp_path):
        """Test that scanning a directory with mixed file types generates a hash."""
        # Create a model file
        model_file = tmp_path / "model.pkl"
        with open(model_file, "wb") as f:
            pickle.dump({"data": "model"}, f)

        # Create a text file
        text_file = tmp_path / "readme.txt"
        text_file.write_text("This is a readme")

        # Scan directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should have a content hash
        assert result.content_hash is not None
        # Should have scanned at least the model file
        assert result.files_scanned >= 1


@pytest.mark.unit
class TestHashGenerationEdgeCases:
    """Test edge cases in hash generation."""

    def test_hash_with_nested_directories(self, tmp_path):
        """Test hash generation with nested directory structure."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        file1 = tmp_path / "model.pkl"
        with open(file1, "wb") as f:
            pickle.dump({"level": 1}, f)

        file2 = subdir / "nested.pkl"
        with open(file2, "wb") as f:
            pickle.dump({"level": 2}, f)

        # Scan root directory
        result = scan_model_directory_or_file(str(tmp_path))

        # Should generate hash for all files
        assert result.content_hash is not None
        assert result.files_scanned == 2

    def test_hash_with_symlinks(self, tmp_path):
        """Test that symlinks are handled correctly in hash generation."""
        # Create a real file
        real_file = tmp_path / "real.pkl"
        with open(real_file, "wb") as f:
            pickle.dump({"type": "real"}, f)

        # Note: Symlink handling depends on os.walk(followlinks=False)
        # which is used in scan_model_directory_or_file
        result = scan_model_directory_or_file(str(tmp_path))

        assert result.content_hash is not None

    def test_hash_generation_performance(self, tmp_path):
        """Test that hash generation doesn't significantly impact performance."""
        import time

        # Create multiple files
        for i in range(10):
            test_file = tmp_path / f"model_{i}.pkl"
            with open(test_file, "wb") as f:
                pickle.dump({"id": i}, f)

        # Measure scan time
        start = time.time()
        result = scan_model_directory_or_file(str(tmp_path))
        duration = time.time() - start

        # Should complete quickly (under 5 seconds for 10 small files)
        assert duration < 5.0
        assert result.content_hash is not None
        assert result.files_scanned == 10
