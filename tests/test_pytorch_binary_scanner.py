import struct

from modelaudit.scanners.pytorch_binary_scanner import PyTorchBinaryScanner
from modelaudit.suspicious_symbols import BINARY_CODE_PATTERNS


def test_pytorch_binary_scanner_can_handle(tmp_path):
    """Test that the scanner correctly identifies pytorch binary files."""
    scanner = PyTorchBinaryScanner()

    # Create a mock pytorch binary file
    binary_file = tmp_path / "model.bin"
    # Write some random binary data (not pickle format)
    binary_file.write_bytes(b"\x00\x01\x02\x03" * 100)

    # Should handle .bin files that are not pickle format
    assert scanner.can_handle(str(binary_file))

    # Should not handle directories
    assert not scanner.can_handle(str(tmp_path))

    # Should not handle other extensions
    other_file = tmp_path / "model.txt"
    other_file.write_text("not a binary file")
    assert not scanner.can_handle(str(other_file))


def test_pytorch_binary_scanner_basic_scan(tmp_path):
    """Test basic scanning of a pytorch binary file."""
    scanner = PyTorchBinaryScanner()

    # Create a simple binary file
    binary_file = tmp_path / "model.bin"
    # Write float data that looks like tensor data
    data = struct.pack("f" * 10, *[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    binary_file.write_bytes(data * 10)

    result = scanner.scan(str(binary_file))

    assert result.success
    assert result.bytes_scanned == len(data) * 10

    # Should have no file type validation warnings (.bin files with unknown headers are valid)
    validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]
    assert len(validation_issues) == 0


def test_pytorch_binary_scanner_code_patterns(tmp_path):
    """Test detection of embedded code patterns."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with embedded code patterns
    binary_file = tmp_path / "malicious.bin"
    pattern_import = BINARY_CODE_PATTERNS[0]
    pattern_system = next(p for p in BINARY_CODE_PATTERNS if p.startswith(b"os.system"))
    data = b"\x00" * 100 + pattern_import + b"\n" + pattern_system + b"\x00" * 100
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success
    assert len(result.issues) > 0

    # Check that we found the code patterns
    found_import = False
    found_system = False
    for issue in result.issues:
        if "import os" in issue.message:
            found_import = True
        if "os.system" in issue.message:
            found_system = True

    assert found_import
    assert found_system


def test_pytorch_binary_scanner_executable_signatures_at_start(tmp_path):
    """Test detection of executable signatures at file start."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with Windows executable signature at the beginning
    binary_file = tmp_path / "real_exe.bin"
    # MZ header at offset 0 - should be detected
    data = b"MZ" + b"\x00" * 1000
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should find the Windows executable at offset 0
    found_pe = False
    for issue in result.issues:
        if "Windows executable" in issue.message and "(offset: 0)" in issue.location:
            found_pe = True

    assert found_pe, "Should detect Windows executable at offset 0"


def test_pytorch_binary_scanner_no_false_positive_mz(tmp_path):
    """Test that MZ signature in middle of file is not flagged (false positive fix)."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with MZ signature in the middle (like BERT weights might have)
    binary_file = tmp_path / "bert_weights.bin"
    # Random data that happens to contain MZ in the middle
    import struct

    # Create float data
    floats = [0.1, 0.2, 0.3, 0.4, 0.5]
    float_data = struct.pack("f" * len(floats), *floats)
    # Add MZ signature in the middle of the file
    data = b"\x00" * 500 + b"MZ" + b"\x00" * 500 + float_data
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should NOT find Windows executable (MZ is not at offset 0)
    found_pe = False
    for issue in result.issues:
        if "Windows executable" in issue.message:
            found_pe = True

    assert not found_pe, "Should NOT detect Windows executable when MZ is in middle of file"


def test_pytorch_binary_scanner_longer_signatures_still_detected(tmp_path):
    """Test that longer executable signatures are still detected regardless of position."""
    scanner = PyTorchBinaryScanner()

    # Create a binary file with longer signatures in the middle
    binary_file = tmp_path / "with_elf.bin"
    # ELF signature is 4 bytes - should still be detected even in middle
    data = b"\x00" * 100 + b"\x7fELF" + b"\x00" * 100
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success

    # Should find the ELF executable (longer signature)
    found_elf = False
    for issue in result.issues:
        if "Linux executable" in issue.message:
            found_elf = True

    assert found_elf, "Should detect Linux executable (4-byte signature) even in middle of file"


def test_pytorch_binary_scanner_blacklist_patterns(tmp_path):
    """Test detection of blacklisted patterns."""
    config = {"blacklist_patterns": ["CONFIDENTIAL", "SECRET_KEY"]}
    scanner = PyTorchBinaryScanner(config)

    # Create a binary file with blacklisted patterns
    binary_file = tmp_path / "with_blacklist.bin"
    data = b"\x00" * 50 + b"CONFIDENTIAL_DATA" + b"\x00" * 50 + b"SECRET_KEY=12345" + b"\x00" * 50
    binary_file.write_bytes(data)

    result = scanner.scan(str(binary_file))

    assert result.success
    assert len(result.issues) >= 2

    # Check that we found the blacklisted patterns
    found_confidential = False
    found_secret = False
    for issue in result.issues:
        if "CONFIDENTIAL" in issue.message:
            found_confidential = True
        if "SECRET_KEY" in issue.message:
            found_secret = True

    assert found_confidential
    assert found_secret


def test_pytorch_binary_scanner_small_file(tmp_path):
    """Test handling of suspiciously small files."""
    scanner = PyTorchBinaryScanner()

    # Create a very small binary file
    binary_file = tmp_path / "tiny.bin"
    binary_file.write_bytes(b"\x00" * 50)  # 50 bytes

    result = scanner.scan(str(binary_file))

    assert result.success
    assert len(result.issues) > 0

    # Check for small file warning
    found_small_warning = False
    for issue in result.issues:
        if "small" in issue.message.lower():
            found_small_warning = True

    assert found_small_warning


def test_filetype_detection_for_bin_files(tmp_path):
    """Test that filetype detection correctly identifies different .bin formats."""
    from modelaudit.utils.filetype import detect_file_format

    # Test pickle format .bin
    pickle_bin = tmp_path / "pickle.bin"
    pickle_bin.write_bytes(b"\x80\x03}q\x00.")  # Pickle protocol 3
    assert detect_file_format(str(pickle_bin)) == "pickle"

    # Test safetensors format .bin
    safetensors_bin = tmp_path / "safetensors.bin"
    safetensors_bin.write_bytes(b'{"__metadata__": {"format": "pt"}}' + b"\x00" * 100)
    assert detect_file_format(str(safetensors_bin)) == "safetensors"

    # Test ONNX format .bin
    onnx_bin = tmp_path / "onnx.bin"
    onnx_bin.write_bytes(b"\x08\x01\x12\x00" + b"onnx.proto" + b"\x00" * 100)
    assert detect_file_format(str(onnx_bin)) == "onnx"

    # Test raw binary format .bin
    raw_bin = tmp_path / "raw.bin"
    raw_bin.write_bytes(b"\x00\x01\x02\x03" * 100)
    assert detect_file_format(str(raw_bin)) == "pytorch_binary"


def test_pickle_scanner_handles_pickle_bin_files(tmp_path):
    """Test that pickle scanner correctly handles .bin files with pickle content."""
    from modelaudit.scanners.pickle_scanner import PickleScanner

    scanner = PickleScanner()

    # Create a .bin file with pickle content
    pickle_bin = tmp_path / "model.bin"
    import pickle

    data = {"weights": [1.0, 2.0, 3.0]}
    with open(pickle_bin, "wb") as f:
        pickle.dump(data, f)

    # Should handle pickle .bin files
    assert scanner.can_handle(str(pickle_bin))

    # Scan should work
    result = scanner.scan(str(pickle_bin))
    assert result.success
    assert result.bytes_scanned > 0
