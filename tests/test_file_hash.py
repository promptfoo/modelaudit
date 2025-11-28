"""Tests for file_hash.py SHA256 hashing utility."""

import hashlib
import tempfile
from pathlib import Path

import pytest

from modelaudit.utils.helpers.file_hash import compute_sha256_hash


def test_compute_sha256_hash_small_file():
    """Test SHA256 hash computation for a small file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Hello, World!")
        temp_file = Path(f.name)

    try:
        # Compute hash
        result = compute_sha256_hash(temp_file)

        # Expected hash for "Hello, World!"
        expected = hashlib.sha256(b"Hello, World!").hexdigest()

        assert result == expected
        assert len(result) == 64  # SHA256 produces 64 hex characters
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_empty_file():
    """Test SHA256 hash computation for an empty file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_file = Path(f.name)

    try:
        # Compute hash
        result = compute_sha256_hash(temp_file)

        # Expected hash for empty content
        expected = hashlib.sha256(b"").hexdigest()

        assert result == expected
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_large_file():
    """Test SHA256 hash computation for a large file (chunked reading)."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
        # Write 10 MB of data
        data = b"A" * (10 * 1024 * 1024)
        f.write(data)
        temp_file = Path(f.name)

    try:
        # Compute hash
        result = compute_sha256_hash(temp_file)

        # Expected hash
        expected = hashlib.sha256(data).hexdigest()

        assert result == expected
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_binary_file():
    """Test SHA256 hash computation for a binary file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
        # Write various binary data
        data = bytes(range(256)) * 100  # 25.6 KB of binary data
        f.write(data)
        temp_file = Path(f.name)

    try:
        # Compute hash
        result = compute_sha256_hash(temp_file)

        # Expected hash
        expected = hashlib.sha256(data).hexdigest()

        assert result == expected
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_file_not_found():
    """Test that FileNotFoundError is raised for non-existent file."""
    non_existent = Path("/tmp/this_file_does_not_exist_12345.txt")

    with pytest.raises(FileNotFoundError):
        compute_sha256_hash(non_existent)


def test_compute_sha256_hash_directory():
    """Test that ValueError is raised when path is a directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)

        with pytest.raises(ValueError, match="Path is not a file"):
            compute_sha256_hash(dir_path)


def test_compute_sha256_hash_deterministic():
    """Test that hash computation is deterministic (same file = same hash)."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Deterministic content")
        temp_file = Path(f.name)

    try:
        # Compute hash twice
        hash1 = compute_sha256_hash(temp_file)
        hash2 = compute_sha256_hash(temp_file)

        # Should be identical
        assert hash1 == hash2
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_different_files():
    """Test that different files produce different hashes."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f1:
        f1.write("Content A")
        temp_file1 = Path(f1.name)

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f2:
        f2.write("Content B")
        temp_file2 = Path(f2.name)

    try:
        hash1 = compute_sha256_hash(temp_file1)
        hash2 = compute_sha256_hash(temp_file2)

        # Should be different
        assert hash1 != hash2
    finally:
        temp_file1.unlink()
        temp_file2.unlink()


def test_compute_sha256_hash_custom_chunk_size():
    """Test SHA256 hash computation with custom chunk size."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Custom chunk size test")
        temp_file = Path(f.name)

    try:
        # Compute with different chunk sizes - should produce same result
        hash_default = compute_sha256_hash(temp_file)
        hash_small_chunk = compute_sha256_hash(temp_file, chunk_size=1024)
        hash_large_chunk = compute_sha256_hash(temp_file, chunk_size=1024 * 1024)

        assert hash_default == hash_small_chunk == hash_large_chunk
    finally:
        temp_file.unlink()


def test_compute_sha256_hash_path_types():
    """Test that both Path and string paths work."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Path type test")
        temp_file_path = Path(f.name)
        temp_file_str = str(f.name)

    try:
        # Both should work and produce same result
        hash_path = compute_sha256_hash(temp_file_path)
        hash_str = compute_sha256_hash(temp_file_str)

        assert hash_path == hash_str
    finally:
        temp_file_path.unlink()
