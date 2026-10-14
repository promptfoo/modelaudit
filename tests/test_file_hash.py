"""Tests for file_hash.py SHA256 hashing utility."""

import hashlib
from pathlib import Path

import pytest

from modelaudit.utils.helpers.file_hash import compute_sha256_hash


def test_compute_sha256_hash_small_file(tmp_path: Path) -> None:
    """Test SHA256 hash computation for a small file."""
    temp_file = tmp_path / "input.bin"
    temp_file.touch(mode=0o600)
    temp_file.write_text("Hello, World!")

    # Compute hash
    result = compute_sha256_hash(temp_file)

    # Expected hash for "Hello, World!"
    expected = hashlib.sha256(b"Hello, World!").hexdigest()

    assert result == expected
    assert len(result) == 64  # SHA256 produces 64 hex characters
    # Verify that hashing preserved the input and released its handle.
    temp_file.unlink()


def test_compute_sha256_hash_empty_file(tmp_path: Path) -> None:
    """Test SHA256 hash computation for an empty file."""
    temp_file = tmp_path / "input.bin"
    temp_file.touch(mode=0o600)

    # Compute hash
    result = compute_sha256_hash(temp_file)

    # Expected hash for empty content
    expected = hashlib.sha256(b"").hexdigest()

    assert result == expected
    temp_file.unlink()


def test_compute_sha256_hash_large_file(tmp_path: Path) -> None:
    """Test SHA256 hash computation for a large file (chunked reading)."""
    temp_file = tmp_path / "input.bin"
    # Write 10 MB of data
    data = b"A" * (10 * 1024 * 1024)
    temp_file.touch(mode=0o600)
    temp_file.write_bytes(data)

    # Compute hash
    result = compute_sha256_hash(temp_file)

    # Expected hash
    expected = hashlib.sha256(data).hexdigest()

    assert result == expected
    temp_file.unlink()


def test_compute_sha256_hash_binary_file(tmp_path: Path) -> None:
    """Test SHA256 hash computation for a binary file."""
    temp_file = tmp_path / "input.bin"
    # Write various binary data
    data = bytes(range(256)) * 100  # 25.6 KB of binary data
    temp_file.touch(mode=0o600)
    temp_file.write_bytes(data)

    # Compute hash
    result = compute_sha256_hash(temp_file)

    # Expected hash
    expected = hashlib.sha256(data).hexdigest()

    assert result == expected
    temp_file.unlink()


def test_compute_sha256_hash_file_not_found(tmp_path: Path) -> None:
    """Test that FileNotFoundError is raised for non-existent file."""
    non_existent = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        compute_sha256_hash(non_existent)


def test_compute_sha256_hash_directory(tmp_path: Path) -> None:
    """Test that ValueError is raised when path is a directory."""
    with pytest.raises(ValueError, match="Path is not a file"):
        compute_sha256_hash(tmp_path)


def test_compute_sha256_hash_deterministic(tmp_path: Path) -> None:
    """Test that hash computation is deterministic (same file = same hash)."""
    temp_file = tmp_path / "input.bin"
    temp_file.touch(mode=0o600)
    temp_file.write_text("Deterministic content")

    # Compute hash twice
    hash1 = compute_sha256_hash(temp_file)
    hash2 = compute_sha256_hash(temp_file)

    # Should be identical
    assert hash1 == hash2
    temp_file.unlink()


def test_compute_sha256_hash_different_files(tmp_path: Path) -> None:
    """Test that different files produce different hashes."""
    temp_file1 = tmp_path / "first.bin"
    temp_file1.touch(mode=0o600)
    temp_file1.write_text("Content A")

    temp_file2 = tmp_path / "second.bin"
    temp_file2.touch(mode=0o600)
    temp_file2.write_text("Content B")

    hash1 = compute_sha256_hash(temp_file1)
    hash2 = compute_sha256_hash(temp_file2)

    # Should be different
    assert hash1 != hash2
    temp_file1.unlink()
    temp_file2.unlink()


def test_compute_sha256_hash_custom_chunk_size(tmp_path: Path) -> None:
    """Test SHA256 hash computation with custom chunk size."""
    temp_file = tmp_path / "input.bin"
    temp_file.touch(mode=0o600)
    temp_file.write_text("Custom chunk size test")

    # Compute with different chunk sizes - should produce same result
    hash_default = compute_sha256_hash(temp_file)
    hash_small_chunk = compute_sha256_hash(temp_file, chunk_size=1024)
    hash_large_chunk = compute_sha256_hash(temp_file, chunk_size=1024 * 1024)

    assert hash_default == hash_small_chunk == hash_large_chunk
    temp_file.unlink()


def test_compute_sha256_hash_path_types(tmp_path: Path) -> None:
    """Test that both Path and string paths work."""
    temp_file_path = tmp_path / "input.bin"
    temp_file_path.touch(mode=0o600)
    temp_file_path.write_text("Path type test")

    temp_file_str = str(temp_file_path)

    # Both should work and produce same result
    hash_path = compute_sha256_hash(temp_file_path)
    hash_str = compute_sha256_hash(temp_file_str)

    assert hash_path == hash_str
    temp_file_path.unlink()
