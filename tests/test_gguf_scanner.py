"""Comprehensive tests for the GGUF scanner."""

import struct

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.gguf_scanner import GgufScanner


def _write_minimal_gguf(path, n_kv=1, n_tensors=0, kv_key=b"test", kv_value=b"val"):
    """Create a minimal valid GGUF file for testing."""
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", n_tensors))  # tensor count
        f.write(struct.pack("<Q", n_kv))  # kv count

        # Metadata
        if n_kv > 0:
            f.write(struct.pack("<Q", len(kv_key)))  # key length
            f.write(kv_key)  # key
            f.write(struct.pack("<I", 8))  # value type (string)
            f.write(struct.pack("<Q", len(kv_value)))  # value length
            f.write(kv_value)  # value


def _write_comprehensive_gguf(path):
    """Create a comprehensive GGUF file with tensors for testing."""
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # Tensor info
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 1))  # dimensions
        f.write(struct.pack("<Q", 8))  # dimension size
        f.write(struct.pack("<I", 0))  # f32 tensor type
        offset = f.tell() + 8
        f.write(struct.pack("<Q", offset))  # tensor offset

        # Tensor data (8 * 4 bytes for f32)
        f.write(b"\0" * 32)


def _write_ggml_file(path):
    """Create a basic GGML file for testing."""
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(struct.pack("<I", 1))  # version
        f.write(b"\0" * 24)  # padding to minimum size


def _write_ggml_variant_file(path, magic):
    """Create a GGML variant file with custom magic."""
    with open(path, "wb") as f:
        f.write(magic)
        f.write(struct.pack("<I", 1))
        f.write(b"\0" * 24)


def test_gguf_scanner_can_handle_gguf(tmp_path):
    """Test that scanner can handle GGUF files."""
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_can_handle_ggml(tmp_path):
    """Test that scanner can handle GGML files."""
    path = tmp_path / "model.ggml"
    _write_ggml_file(path)
    assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_can_handle_ggml_variants(tmp_path):
    """Scanner handles GGML variant magic codes."""
    for magic in [b"GGMF", b"GGJT"]:
        path = tmp_path / f"model_{magic.decode().lower()}.ggml"
        _write_ggml_variant_file(path, magic)
        assert GgufScanner.can_handle(str(path))


def test_gguf_scanner_rejects_invalid_files(tmp_path):
    """Test that scanner rejects invalid files."""
    path = tmp_path / "invalid.gguf"
    with open(path, "wb") as f:
        f.write(b"INVALID")
    assert not GgufScanner.can_handle(str(path))


def test_gguf_scanner_basic_scan(tmp_path):
    """Test basic GGUF scanning functionality."""
    path = tmp_path / "model.gguf"
    _write_minimal_gguf(path)
    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "gguf"
    assert result.metadata["n_kv"] == 1
    assert result.metadata["n_tensors"] == 0


def test_gguf_scanner_comprehensive_scan(tmp_path):
    """Test comprehensive GGUF scanning with tensors."""
    path = tmp_path / "model.gguf"
    _write_comprehensive_gguf(path)
    scanner = GgufScanner()
    result = scanner.scan(str(path))
    assert result.success
    assert result.metadata["n_tensors"] == 1
    assert len(result.metadata["tensors"]) == 1
    assert result.metadata["tensors"][0]["name"] == "weight"


def test_gguf_scanner_large_kv_count(tmp_path):
    """Test detection of suspiciously large KV counts."""
    path = tmp_path / "bad.gguf"
    _write_minimal_gguf(path, n_kv=2**31)
    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert "invalid" in str(result.issues[0].message).lower()


def test_gguf_scanner_large_tensor_count(tmp_path):
    """Test detection of suspiciously large tensor counts."""
    path = tmp_path / "bad.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 2**31))  # huge tensor count
        f.write(struct.pack("<Q", 0))  # kv count

    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_gguf_scanner_truncated_file(tmp_path):
    """Test handling of truncated GGUF files."""
    path = tmp_path / "trunc.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 5))  # Claims 5 KV pairs but file ends

    result = GgufScanner().scan(str(path))
    assert not result.success or any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_gguf_scanner_suspicious_key_paths(tmp_path):
    """Test detection of suspicious key names with path traversal."""
    path = tmp_path / "suspicious.gguf"
    _write_minimal_gguf(path, kv_key=b"../../../etc/passwd", kv_value=b"root")

    result = GgufScanner().scan(str(path))
    assert any("path traversal" in i.message.lower() for i in result.issues)


def test_gguf_scanner_suspicious_values(tmp_path):
    """Test detection of suspicious metadata values."""
    path = tmp_path / "suspicious.gguf"
    _write_minimal_gguf(path, kv_key=b"command", kv_value=b"rm -rf /")

    result = GgufScanner().scan(str(path))
    assert any("suspicious" in i.message.lower() for i in result.issues)


def test_gguf_scanner_string_length_security(tmp_path):
    """Test security checks for string lengths."""
    path = tmp_path / "long_string.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count
        f.write(struct.pack("<Q", 2**31))  # extremely long key
        # File ends here, should trigger error

    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_ggml_scanner_basic(tmp_path):
    """Test basic GGML file scanning."""
    path = tmp_path / "model.ggml"
    _write_ggml_file(path)

    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "ggml"
    assert result.metadata["version"] == 1


def test_ggml_variant_scanner_basic(tmp_path):
    """Ensure GGML variants are scanned correctly."""
    path = tmp_path / "model.ggmf"
    _write_ggml_variant_file(path, b"GGMF")
    result = GgufScanner().scan(str(path))
    assert result.success
    assert result.metadata["format"] == "ggml"
    assert result.metadata.get("magic") == "GGMF"


def test_ggml_scanner_suspicious_version(tmp_path):
    """Test detection of suspicious GGML versions."""
    path = tmp_path / "suspicious.ggml"
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(struct.pack("<I", 99999))  # suspicious version
        f.write(b"\0" * 24)

    result = GgufScanner().scan(str(path))
    assert any("suspicious" in i.message.lower() for i in result.issues)


def test_ggml_scanner_truncated(tmp_path):
    """Test handling of truncated GGML files."""
    path = tmp_path / "trunc.ggml"
    with open(path, "wb") as f:
        f.write(b"GGML")
        f.write(b"\0" * 10)  # Too short

    result = GgufScanner().scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_gguf_scanner_invalid_alignment(tmp_path):
    """Test detection of invalid alignment values."""
    path = tmp_path / "bad_align.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Bad alignment value
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 3))  # Invalid alignment (not multiple of 8)

    result = GgufScanner().scan(str(path))
    assert any("alignment" in i.message.lower() for i in result.issues)


def test_gguf_scanner_tensor_dimension_limits(tmp_path):
    """Test detection of tensors with too many dimensions."""
    path = tmp_path / "many_dims.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Minimal metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", 32))

        # Align to 32
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # Tensor with too many dimensions
        name = b"tensor"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 20))  # 20 dimensions (suspicious)

        # Don't write the rest as it would be too long

    result = GgufScanner().scan(str(path))
    assert any("suspicious" in i.message.lower() and "dimensions" in i.message.lower() for i in result.issues)


def test_gguf_scanner_excessive_tensor_dimensions_dos_protection(tmp_path):
    """Test DoS protection against tensors with excessive dimensions."""
    path = tmp_path / "dos_dimensions.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 1))  # kv count

        # Minimal metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", 32))

        # Align to 32
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # Tensor with excessive dimensions (DoS attack attempt)
        name = b"dos_tensor"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 2000))  # 2000 dimensions (triggers DoS protection)

        # Write fake dimension data and tensor metadata
        # In a real attack, this would be much larger
        for _ in range(2000):
            f.write(struct.pack("<Q", 10))  # dimension size
        f.write(struct.pack("<I", 0))  # tensor type
        f.write(struct.pack("<Q", 1000))  # offset

    result = GgufScanner().scan(str(path))

    # Should detect the DoS attempt
    assert any(
        "excessive dimensions" in i.message.lower() and i.severity == IssueSeverity.CRITICAL for i in result.issues
    )

    # Should mention skipping for security
    assert any("skipping for security" in i.message.lower() for i in result.issues)


def test_gguf_scanner_file_extensions(tmp_path):
    """Test that scanner handles different file extensions correctly."""
    # Test .gguf extension
    gguf_path = tmp_path / "model.gguf"
    _write_minimal_gguf(gguf_path)
    assert GgufScanner.can_handle(str(gguf_path))

    # Test .ggml extension
    ggml_path = tmp_path / "model.ggml"
    _write_ggml_file(ggml_path)
    assert GgufScanner.can_handle(str(ggml_path))

    # Test unsupported extension
    txt_path = tmp_path / "model.txt"
    with open(txt_path, "w") as f:
        f.write("not a model")
    assert not GgufScanner.can_handle(str(txt_path))


def test_gguf_scanner_metadata_types(tmp_path):
    """Test handling of different metadata value types."""
    path = tmp_path / "types.gguf"
    with open(path, "wb") as f:
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))  # tensor count
        f.write(struct.pack("<Q", 3))  # kv count

        # String value
        key1 = b"string_key"
        f.write(struct.pack("<Q", len(key1)))
        f.write(key1)
        f.write(struct.pack("<I", 8))  # STRING
        val1 = b"string_value"
        f.write(struct.pack("<Q", len(val1)))
        f.write(val1)

        # Int32 value
        key2 = b"int_key"
        f.write(struct.pack("<Q", len(key2)))
        f.write(key2)
        f.write(struct.pack("<I", 5))  # INT32
        f.write(struct.pack("<i", 42))

        # Float32 value
        key3 = b"float_key"
        f.write(struct.pack("<Q", len(key3)))
        f.write(key3)
        f.write(struct.pack("<I", 6))  # FLOAT32
        f.write(struct.pack("<f", 3.14))

    result = GgufScanner().scan(str(path))
    assert result.success
    assert "string_key" in result.metadata["metadata"]
    assert "int_key" in result.metadata["metadata"]
    assert "float_key" in result.metadata["metadata"]


def test_gguf_scanner_error_handling(tmp_path):
    """Test various error conditions."""
    scanner = GgufScanner()

    # Test non-existent file
    result = scanner.scan("non_existent_file.gguf")
    assert not result.success

    # Test directory instead of file
    dir_path = tmp_path / "not_a_file"
    dir_path.mkdir()
    result = scanner.scan(str(dir_path))
    assert not result.success


def test_gguf_scanner_invalid_tensor_dimensions(tmp_path):
    """Test handling of tensors with invalid dimensions (regression test for dimension bug)."""
    path = tmp_path / "invalid_dims.gguf"
    with open(path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 2))  # tensor count - two tensors to test both cases
        f.write(struct.pack("<Q", 1))  # kv count

        # Minimal metadata
        key = b"general.alignment"
        f.write(struct.pack("<Q", len(key)))
        f.write(key)
        f.write(struct.pack("<I", 4))  # UINT32
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        pad = (32 - (f.tell() % 32)) % 32
        f.write(b"\0" * pad)

        # First tensor with invalid dimensions: [10, 0, 5] - has zero dimension
        name1 = b"tensor_with_zero"
        f.write(struct.pack("<Q", len(name1)))
        f.write(name1)
        f.write(struct.pack("<I", 3))  # 3 dimensions
        f.write(struct.pack("<Q", 10))  # first dimension
        f.write(struct.pack("<Q", 0))  # zero dimension (invalid!)
        f.write(struct.pack("<Q", 5))  # third dimension
        f.write(struct.pack("<I", 0))  # f32 tensor type
        offset1 = 100  # dummy offset
        f.write(struct.pack("<Q", offset1))

        # Second tensor with invalid dimensions: [10, -1, 5] - has negative dimension
        name2 = b"tensor_with_negative"
        f.write(struct.pack("<Q", len(name2)))
        f.write(name2)
        f.write(struct.pack("<I", 3))  # 3 dimensions
        f.write(struct.pack("<Q", 10))  # first dimension
        f.write(struct.pack("<q", -1))  # negative dimension (invalid!)
        f.write(struct.pack("<Q", 5))  # third dimension
        f.write(struct.pack("<I", 0))  # f32 tensor type
        offset2 = 200  # dummy offset
        f.write(struct.pack("<Q", offset2))

    result = GgufScanner().scan(str(path))

    # The scan should succeed but report the invalid dimensions
    assert result.success

    # Should have warnings about both invalid dimensions
    warning_messages = [issue.message for issue in result.issues]

    # Check for zero dimension warning
    assert any("tensor_with_zero" in msg and "invalid dimension: 0" in msg for msg in warning_messages)

    # Check for negative dimension warning (the exact value depends on how it's interpreted)
    assert any("tensor_with_negative" in msg and "invalid dimension" in msg for msg in warning_messages)

    # Should have exactly 2 warnings (one for each invalid dimension)
    dimension_warnings = [msg for msg in warning_messages if "invalid dimension" in msg]
    assert len(dimension_warnings) == 2

    # Verify that tensors metadata is still populated (shows parsing continued)
    assert "tensors" in result.metadata
    assert len(result.metadata["tensors"]) == 2
