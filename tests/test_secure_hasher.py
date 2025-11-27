"""Tests for secure_hasher.py including aggregate hash computation."""

import hashlib
import tempfile
from pathlib import Path

from modelaudit.utils.helpers.secure_hasher import (
    SecureFileHasher,
    compute_aggregate_hash,
    hash_file_secure,
    verify_file_hash,
)


def test_compute_aggregate_hash_empty():
    """Test aggregate hash with empty list."""
    result = compute_aggregate_hash([])
    # Hash of empty string
    expected = hashlib.sha256(b"").hexdigest()
    assert result == expected
    assert len(result) == 64


def test_compute_aggregate_hash_single():
    """Test aggregate hash with single hash."""
    file_hash = "a" * 64
    result = compute_aggregate_hash([file_hash])

    # Should hash the single hash string
    expected = hashlib.sha256(file_hash.encode("utf-8")).hexdigest()
    assert result == expected
    assert len(result) == 64


def test_compute_aggregate_hash_multiple():
    """Test aggregate hash with multiple hashes."""
    hashes = [
        "abc123" + "0" * 58,  # 64 chars
        "def456" + "1" * 58,  # 64 chars
        "ghi789" + "2" * 58,  # 64 chars
    ]
    result = compute_aggregate_hash(hashes)

    # Verify it's a valid SHA256
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_compute_aggregate_hash_deterministic():
    """Test that aggregate hash is deterministic."""
    hashes = ["hash1" + "a" * 59, "hash2" + "b" * 59, "hash3" + "c" * 59]

    result1 = compute_aggregate_hash(hashes)
    result2 = compute_aggregate_hash(hashes)

    assert result1 == result2


def test_compute_aggregate_hash_order_independent():
    """Test that aggregate hash is order-independent (sorts hashes)."""
    hashes_ordered = ["aaa", "bbb", "ccc", "ddd"]
    hashes_reversed = ["ddd", "ccc", "bbb", "aaa"]
    hashes_random = ["ccc", "aaa", "ddd", "bbb"]

    result1 = compute_aggregate_hash(hashes_ordered)
    result2 = compute_aggregate_hash(hashes_reversed)
    result3 = compute_aggregate_hash(hashes_random)

    # All should be identical (sorted before hashing)
    assert result1 == result2 == result3


def test_compute_aggregate_hash_different_content():
    """Test that different hash lists produce different aggregates."""
    hashes1 = ["hash_a" + "1" * 58, "hash_b" + "2" * 58]
    hashes2 = ["hash_c" + "3" * 58, "hash_d" + "4" * 58]

    result1 = compute_aggregate_hash(hashes1)
    result2 = compute_aggregate_hash(hashes2)

    assert result1 != result2


def test_compute_aggregate_hash_realistic_sha256():
    """Test with realistic SHA256 hashes."""
    # Simulate real file hashes
    hash1 = hashlib.sha256(b"file1 content").hexdigest()
    hash2 = hashlib.sha256(b"file2 content").hexdigest()
    hash3 = hashlib.sha256(b"file3 content").hexdigest()

    hashes = [hash1, hash2, hash3]
    result = compute_aggregate_hash(hashes)

    # Manually compute expected result
    sorted_hashes = sorted(hashes)
    combined = "".join(sorted_hashes)
    expected = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    assert result == expected


def test_secure_file_hasher_basic():
    """Test basic SecureFileHasher functionality."""
    hasher = SecureFileHasher()

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Test content")
        temp_file = f.name

    try:
        result = hasher.hash_file(temp_file)

        # Should have prefix
        assert result.startswith("secure:")
        # Should be valid hash
        hash_part = result.replace("secure:", "")
        assert len(hash_part) == 64
    finally:
        Path(temp_file).unlink()


def test_hash_file_secure_convenience():
    """Test convenience function for secure hashing."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Test content")
        temp_file = f.name

    try:
        result = hash_file_secure(temp_file)

        assert result.startswith("secure:")
        hash_part = result.replace("secure:", "")
        assert len(hash_part) == 64
    finally:
        Path(temp_file).unlink()


def test_verify_file_hash():
    """Test hash verification."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("Test content")
        temp_file = f.name

    try:
        # Hash the file
        file_hash = hash_file_secure(temp_file)

        # Verify should succeed
        assert verify_file_hash(temp_file, file_hash) is True

        # Wrong hash should fail
        wrong_hash = "secure:" + "0" * 64
        assert verify_file_hash(temp_file, wrong_hash) is False
    finally:
        Path(temp_file).unlink()


def test_compute_aggregate_hash_with_model_scan():
    """Test aggregate hash in a model scanning scenario."""
    # Simulate scanning multiple model files
    model_files = [
        b"model weights layer 1",
        b"model weights layer 2",
        b"model config",
        b"tokenizer vocab",
    ]

    # Compute individual file hashes
    file_hashes = [hashlib.sha256(content).hexdigest() for content in model_files]

    # Compute aggregate
    aggregate = compute_aggregate_hash(file_hashes)

    # Verify properties
    assert len(aggregate) == 64
    assert aggregate != file_hashes[0]  # Different from any individual hash

    # Same files in different order should produce same aggregate
    shuffled_hashes = [file_hashes[2], file_hashes[0], file_hashes[3], file_hashes[1]]
    aggregate2 = compute_aggregate_hash(shuffled_hashes)
    assert aggregate == aggregate2


def test_compute_aggregate_hash_unicode():
    """Test that aggregate hash handles unicode correctly."""
    hashes = [
        hashlib.sha256("file1_émoji_🎉".encode()).hexdigest(),
        hashlib.sha256("file2_日本語".encode()).hexdigest(),
        hashlib.sha256("file3_العربية".encode()).hexdigest(),
    ]

    result = compute_aggregate_hash(hashes)

    # Should work without errors
    assert len(result) == 64
    assert isinstance(result, str)


def test_compute_aggregate_hash_large_list():
    """Test aggregate hash with large list of hashes (simulating many model files)."""
    # Simulate scanning 1000 model files
    file_hashes = [hashlib.sha256(f"file_{i}".encode()).hexdigest() for i in range(1000)]

    result = compute_aggregate_hash(file_hashes)

    assert len(result) == 64
    # Should complete quickly even with many files


def test_compute_aggregate_hash_duplicates():
    """Test that duplicate hashes are handled correctly."""
    # Same hash repeated (e.g., identical sharded files)
    duplicate_hash = "a" * 64
    hashes = [duplicate_hash] * 5

    result = compute_aggregate_hash(hashes)

    # Should still produce valid hash
    assert len(result) == 64

    # Should be deterministic
    result2 = compute_aggregate_hash(hashes)
    assert result == result2


def test_secure_file_hasher_get_hash_info():
    """Test hash info extraction."""
    hasher = SecureFileHasher()

    secure_hash = "secure:abc123"
    info = hasher.get_hash_info(secure_hash)

    assert info["method"] == "full_hash"
    assert info["algorithm"] == "blake2b"
    assert info["security_level"] == "high"
    assert info["hash"] == "abc123"


def test_secure_file_hasher_fingerprint_info():
    """Test fingerprint hash info extraction."""
    hasher = SecureFileHasher()

    fingerprint_hash = "fingerprint:def456"
    info = hasher.get_hash_info(fingerprint_hash)

    assert info["method"] == "enhanced_fingerprint"
    assert info["algorithm"] == "blake2b"
    assert info["security_level"] == "medium"
    assert info["hash"] == "def456"
