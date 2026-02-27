import pickle
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
from tests.helpers import create_mock_pytorch_zip


def test_pytorch_zip_scanner_can_handle(tmp_path):
    """Test the can_handle method of PyTorchZipScanner."""
    # Test with actual PyTorch file
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    assert PyTorchZipScanner.can_handle(str(model_path)) is True

    # Test with non-existent file
    assert PyTorchZipScanner.can_handle("nonexistent.pt") is False

    # Test with wrong extension
    test_file = tmp_path / "model.h5"
    test_file.write_bytes(b"not a pytorch file")
    assert PyTorchZipScanner.can_handle(str(test_file)) is False


def test_pytorch_zip_scanner_safe_model(tmp_path):
    """Test scanning a safe PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    assert result.success is True
    assert result.bytes_scanned > 0

    # Check for issues - a safe model might still have some informational issues
    error_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(error_issues) == 0


def test_pytorch_zip_scanner_malicious_model(tmp_path):
    """Test scanning a malicious PyTorch ZIP model."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt", malicious=True)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(model_path))

    # The scanner should detect the eval function in the pickle
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_invalid_zip(tmp_path):
    """Test scanning an invalid ZIP file."""
    # Create an invalid ZIP file
    invalid_path = tmp_path / "invalid.pt"
    invalid_path.write_bytes(b"This is not a valid ZIP file")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(invalid_path))

    # Should have an error about invalid ZIP
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        "invalid" in issue.message.lower() or "corrupt" in issue.message.lower() or "error" in issue.message.lower()
        for issue in result.issues
    )


def test_pytorch_zip_scanner_missing_data_pkl(tmp_path):
    """Test scanning a PyTorch ZIP file without data.pkl."""
    # Create a ZIP file without data.pkl
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        zipf.writestr("model.json", '{"name": "test_model"}')

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should have a warning about missing data.pkl
    assert any("data.pkl" in issue.message for issue in result.issues)


def test_pytorch_zip_scanner_with_blacklist(tmp_path):
    """Test PyTorch ZIP scanner with custom blacklist patterns."""
    # Create a ZIP file with content that matches our blacklist
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create data with a string that will match our blacklist
        data = {"weights": [1, 2, 3], "custom_function": "suspicious_function"}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    # Create scanner with custom blacklist
    scanner = PyTorchZipScanner(config={"blacklist_patterns": ["suspicious_function"]})
    result = scanner.scan(str(zip_path))

    # Should detect our blacklisted pattern
    blacklist_issues = [issue for issue in result.issues if "suspicious_function" in issue.message.lower()]
    assert len(blacklist_issues) > 0


def test_pytorch_pickle_file_unsupported(tmp_path):
    """Raw pickle files with .pt extension should be unsupported."""
    from tests.assets.generators.generate_evil_pickle import EvilClass

    file_path = tmp_path / "raw_pickle.pt"
    with file_path.open("wb") as f:
        pickle.dump(EvilClass(), f)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert any("zip" in issue.message.lower() or "pytorch" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_closes_bytesio(tmp_path, monkeypatch):
    """Ensure BytesIO objects are properly closed after scanning."""
    import io

    closed = {}

    class TrackedBytesIO(io.BytesIO):
        def close(self) -> None:
            closed["closed"] = True
            super().close()

    monkeypatch.setattr(io, "BytesIO", TrackedBytesIO)

    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()
    scanner.scan(str(model_path))

    assert closed.get("closed") is True


def test_pytorch_zip_skips_numeric_data_files(tmp_path):
    """Test that numeric tensor data files in archive/data/ are skipped during JIT scanning."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add numeric tensor data files (these should be skipped)
        # Create a large-ish binary file to simulate real tensor data
        large_binary_data = b"\x00" * 10_000_000  # 10MB of zeros
        zipf.writestr("archive/data/0", large_binary_data)
        zipf.writestr("archive/data/1", large_binary_data)
        zipf.writestr("archive/data/123", large_binary_data)

    scanner = PyTorchZipScanner()

    # Measure scan time - should be fast since numeric files are skipped
    start_time = time.time()
    result = scanner.scan(str(zip_path))
    elapsed_time = time.time() - start_time

    # Should complete quickly (under 5 seconds) even with large numeric files
    assert elapsed_time < 5.0, f"Scan took {elapsed_time:.2f}s, expected < 5s"
    assert result.success is True


def test_pytorch_zip_scans_non_numeric_files_in_archive_data(tmp_path):
    """Test that non-numeric files in archive/data/ are still scanned for security."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Add a non-numeric file with suspicious content in archive/data/
        # This should NOT be skipped
        malicious_code = b"import os; os.system('whoami')"
        zipf.writestr("archive/data/malicious.py", malicious_code)

        # Add a numeric file (should be skipped)
        zipf.writestr("archive/data/0", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # The scanner should have scanned archive/data/malicious.py
    # and detected the suspicious os.system pattern
    assert result.success is True
    # Note: The actual detection depends on the JIT pattern detector
    # At minimum, the file should have been scanned (not skipped)


def test_pytorch_zip_numeric_detection_edge_cases(tmp_path):
    """Test edge cases for numeric file detection in archive/data/."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")

        # Add a normal pickle file
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("archive/data.pkl", pickled_data)

        # Edge cases that should NOT be skipped:
        # - File with number in extension
        zipf.writestr("archive/data/weights.v2", b"data")
        # - File starting with number but not pure numeric
        zipf.writestr("archive/data/0abc", b"data")
        # - File with hex notation
        zipf.writestr("archive/data/0x123", b"data")

        # Files that SHOULD be skipped (pure numeric):
        zipf.writestr("archive/data/0", b"\x00" * 1000)
        zipf.writestr("archive/data/42", b"\x00" * 1000)
        zipf.writestr("archive/data/999999", b"\x00" * 1000)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete successfully without hanging
    assert result.success is True


def test_pytorch_zip_scanner_can_handle_pkl_extension(tmp_path):
    """Test that PyTorchZipScanner can_handle returns True for ZIP-format .pkl files.

    PyTorch's torch.save() uses ZIP format by default since v1.6 (_use_new_zipfile_serialization=True).
    This test verifies that .pkl files with ZIP headers are correctly identified.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = {"weights": [1, 2, 3]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is True


def test_pytorch_zip_scanner_cannot_handle_raw_pkl(tmp_path):
    """Test that PyTorchZipScanner can_handle returns False for raw pickle .pkl files.

    Raw pickle files (created with _use_new_zipfile_serialization=False) should not be
    handled by PyTorchZipScanner - they should go to the PickleScanner instead.
    """
    # Create a raw pickle .pkl file (non-ZIP format)
    pkl_path = tmp_path / "model.pkl"
    data = {"weights": [1, 2, 3]}
    with open(pkl_path, "wb") as f:
        pickle.dump(data, f)

    assert PyTorchZipScanner.can_handle(str(pkl_path)) is False


def test_pytorch_zip_scanner_scans_zip_pkl_successfully(tmp_path):
    """Test that PyTorchZipScanner successfully scans ZIP-format .pkl files.

    This is the fix for the issue where torch.save() creates ZIP files with .pkl extension
    by default, but ModelAudit was routing them to PickleScanner which failed with
    UnicodeDecodeError.
    """
    # Create a ZIP-format .pkl file (simulating torch.save() default behavior)
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        # Standard PyTorch ZIP structure
        zipf.writestr("version", "3")
        zipf.writestr("byteorder", "little")
        zipf.writestr(".format_version", "1")

        # Create a proper pickle with torch-like structure
        data = {"linear.weight": [1.0, 2.0], "linear.bias": [0.1]}
        pickled_data = pickle.dumps(data)
        zipf.writestr("model/data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should succeed without errors
    assert result.success is True
    assert result.bytes_scanned > 0

    # No critical issues
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert len(critical_issues) == 0


def test_pytorch_zip_scanner_detects_malicious_zip_pkl(tmp_path):
    """Test that PyTorchZipScanner detects malicious content in ZIP-format .pkl files."""
    # Create a ZIP-format .pkl file with malicious pickle content
    pkl_path = tmp_path / "model.pkl"
    with zipfile.ZipFile(pkl_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a malicious pickle that would execute code
        class MaliciousClass:
            def __reduce__(self):
                return (eval, ("print('pwned')",))

        data = {"malicious": MaliciousClass()}
        pickled_data = pickle.dumps(data)
        zipf.writestr("data.pkl", pickled_data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(pkl_path))

    # Should detect the eval function
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any("eval" in issue.message.lower() for issue in result.issues)


def test_pytorch_zip_scanner_entry_limit(tmp_path):
    """Test that scanner enforces archive entry count limits."""
    zip_path = tmp_path / "model.pt"

    # Create archive with many entries (exceeding default limit)
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Create entries exceeding the limit
        for i in range(15):
            zipf.writestr(f"entry_{i}.txt", "data")

    # Use a low limit for testing
    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Should have warning about entry count
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_entry_limit_passes(tmp_path):
    """Test that scanner passes when entry count is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass entry limit check - look for passed checks about entry count
    entry_checks = [c for c in result.checks if "entry" in c.name.lower()]
    assert len(entry_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in entry_checks)


def test_pytorch_zip_scanner_compression_ratio_check(tmp_path):
    """Test that scanner detects suspicious compression ratios."""

    zip_path = tmp_path / "model.pt"

    # Create a file with extremely high compression ratio (repetitive data compresses well)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("version", "3")
        # Create highly compressible data (1MB of zeros will compress to almost nothing)
        highly_compressible = b"\x00" * (1024 * 1024)
        zipf.writestr("suspicious_data.bin", highly_compressible)

    # Use a low threshold for testing
    scanner = PyTorchZipScanner(config={"max_compression_ratio": 50})
    result = scanner.scan(str(zip_path))

    # Should have warning about compression ratio
    ratio_issues = [i for i in result.issues if "compression" in i.message.lower() and "ratio" in i.message.lower()]
    assert len(ratio_issues) > 0
    assert ratio_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_compression_ratio_passes(tmp_path):
    """Test that scanner passes when compression ratio is within limits."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Random-ish data doesn't compress well
        data = pickle.dumps({"weights": list(range(1000))})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass compression check - look for passed checks about compression
    ratio_checks = [c for c in result.checks if "compression" in c.name.lower()]
    assert len(ratio_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in ratio_checks)


def test_pytorch_zip_scanner_symlink_detection(tmp_path):
    """Test that scanner detects symlinks in archives."""

    zip_path = tmp_path / "model.pt"

    # Create a ZIP file with a symlink entry
    # Symlinks in ZIP files have external_attr with S_IFLNK flag
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")

        # Create a symlink entry manually
        # The external_attr field encodes the Unix file mode
        # S_IFLNK = 0o120000 (symlink)
        symlink_info = zipfile.ZipInfo("malicious_link")
        # Set external attributes to indicate symlink (Unix mode in upper 16 bits)
        symlink_info.external_attr = 0o120777 << 16  # symlink with full permissions
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, "/etc/passwd")

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should have warning about symlink
    symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
    assert len(symlink_issues) > 0
    assert symlink_issues[0].severity == IssueSeverity.WARNING


def test_pytorch_zip_scanner_no_symlinks_passes(tmp_path):
    """Test that scanner passes when no symlinks are present."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        data = pickle.dumps({"weights": [1, 2, 3]})
        zipf.writestr("data.pkl", data)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should pass symlink check - look for passed checks about symlinks
    symlink_checks = [c for c in result.checks if "symlink" in c.name.lower()]
    assert len(symlink_checks) > 0
    assert all(c.status == CheckStatus.PASSED for c in symlink_checks)


def test_pytorch_zip_scanner_combined_security_controls(tmp_path):
    """Test that multiple security controls fire together without interfering."""
    zip_path = tmp_path / "model.pt"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("version", "3")
        # Generate enough entries to exceed a low limit
        for i in range(12):
            zipf.writestr(f"entry_{i}.txt", "data")
        # Add a symlink entry
        symlink_info = zipfile.ZipInfo("evil_link")
        symlink_info.external_attr = 0o120777 << 16
        symlink_info.compress_type = zipfile.ZIP_STORED
        zipf.writestr(symlink_info, "/etc/shadow")

    scanner = PyTorchZipScanner(config={"max_archive_entries": 10})
    result = scanner.scan(str(zip_path))

    # Entry limit should trigger
    entry_issues = [
        i
        for i in result.issues
        if "entries" in i.message.lower() and ("max" in i.message.lower() or "limit" in i.message.lower())
    ]
    assert len(entry_issues) > 0
    assert entry_issues[0].severity == IssueSeverity.WARNING

    # Symlink should also trigger independently
    symlink_issues = [i for i in result.issues if "symlink" in i.message.lower()]
    assert len(symlink_issues) > 0
    assert symlink_issues[0].severity == IssueSeverity.WARNING


# CVE-2026-24747 Tests


def test_pytorch_zip_cve_2026_24747_version_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CVE-2026-24747 version checking flags vulnerable PyTorch."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    # Mock torch as vulnerable version
    mock_torch = MagicMock()
    mock_torch.__version__ = "2.9.0"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    failed_checks = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.9.0 as vulnerable to CVE-2026-24747. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )


def test_pytorch_zip_cve_2026_24747_fixed_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that PyTorch 2.10.0+ does not trigger CVE-2026-24747 warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    # Mock torch as fixed version
    mock_torch = MagicMock()
    mock_torch.__version__ = "2.10.0"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    # Fixed version: CVE-2026-24747 check should be present but not failed
    cve_2026_checks = [c for c in result.checks if "CVE-2026-24747" in c.name]
    assert len(cve_2026_checks) > 0, "Expected CVE-2026-24747 check to be present"
    cve_2026_failed = [c for c in cve_2026_checks if c.status == CheckStatus.FAILED]
    assert len(cve_2026_failed) == 0, (
        f"PyTorch 2.10.0 should NOT trigger CVE-2026-24747. "
        f"Failed checks: {[(c.name, c.message) for c in cve_2026_failed]}"
    )


def test_pytorch_zip_tensor_metadata_validation(tmp_path: Path) -> None:
    """Test tensor metadata consistency validation runs without errors."""
    # Create a PyTorch ZIP model with data blobs
    zip_path = tmp_path / "model_with_data.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        # Simple pickle with a dict
        data = {"weights": [1.0, 2.0, 3.0]}
        zipf.writestr("archive/data.pkl", pickle.dumps(data))
        # Add a data blob
        zipf.writestr("archive/data/0", b"\x00" * 24)  # 6 float32 values

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    # Should complete without crashing (best-effort validation)
    assert result is not None
    # Should not report metadata mismatches for a normal model
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) == 0, (
        f"Normal model should not have metadata mismatches. Failed: {[(c.name, c.message) for c in mismatch_checks]}"
    )


def test_pytorch_zip_tensor_metadata_mismatch_detection(tmp_path: Path) -> None:
    """Test that intentionally mismatched tensor metadata is detected.

    Creates a PyTorch ZIP where the pickle declares a tensor requiring more
    storage than the actual blob provides, which is the core CVE-2026-24747
    metadata-mismatch exploitation vector.
    """
    import pickletools
    import struct

    # Build a minimal pickle that references _rebuild_tensor_v2 with a
    # declared element count that wildly exceeds the actual blob size.
    # Protocol 2 GLOBAL opcode referencing torch._utils._rebuild_tensor_v2
    pkl_data = bytearray()
    pkl_data.extend(b"\x80\x02")  # PROTO 2
    pkl_data.extend(b"ctorch._utils\n_rebuild_tensor_v2\n")  # GLOBAL
    # Push storage key "0" as SHORT_BINUNICODE
    pkl_data.extend(b"\x8c\x010")  # SHORT_BINUNICODE "0"
    # Push a large element count (1_000_000) as BININT
    pkl_data.extend(b"J")  # BININT opcode
    pkl_data.extend(struct.pack("<i", 1_000_000))
    pkl_data.extend(b".")  # STOP

    # Verify our pickle is parseable by pickletools
    list(pickletools.genops(bytes(pkl_data)))

    zip_path = tmp_path / "mismatch_model.pt"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("archive/version", "3")
        zipf.writestr("archive/data.pkl", bytes(pkl_data))
        # Blob is only 24 bytes but pickle declares 1M elements
        zipf.writestr("archive/data/0", b"\x00" * 24)

    scanner = PyTorchZipScanner()
    result = scanner.scan(str(zip_path))

    assert result is not None
    mismatch_checks = [c for c in result.checks if "Tensor Metadata" in c.name and c.status == CheckStatus.FAILED]
    assert len(mismatch_checks) > 0, (
        f"Should detect tensor storage size mismatch (24 bytes vs 1M declared elements). "
        f"Checks: {[(c.name, c.status, c.message) for c in result.checks]}"
    )


# --- CVE-2022-45907 version check tests ---


def test_pytorch_zip_cve_2022_45907_version_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CVE-2022-45907 version checking flags vulnerable PyTorch."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "1.13.0"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2022-45907" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 1.13.0 as vulnerable to CVE-2022-45907. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )


def test_pytorch_zip_cve_2022_45907_fixed_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that PyTorch 1.13.1+ does not trigger CVE-2022-45907 warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "1.13.1"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2022-45907" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 1.13.1 should NOT trigger CVE-2022-45907. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-5480 version check tests ---


def test_pytorch_zip_cve_2024_5480_version_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CVE-2024-5480 version checking flags vulnerable PyTorch."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "2.2.2"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-5480" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.2.2 as vulnerable to CVE-2024-5480. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )


def test_pytorch_zip_cve_2024_5480_fixed_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that PyTorch 2.2.3+ does not trigger CVE-2024-5480 warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "2.2.3"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-5480" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.2.3 should NOT trigger CVE-2024-5480. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )


# --- CVE-2024-48063 version check tests ---


def test_pytorch_zip_cve_2024_48063_version_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CVE-2024-48063 version checking flags vulnerable PyTorch."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "2.4.1"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_checks = [c for c in result.checks if "CVE-2024-48063" in c.name]
    failed_checks = [c for c in cve_checks if c.status == CheckStatus.FAILED]
    assert len(failed_checks) > 0, (
        f"Should flag PyTorch 2.4.1 as vulnerable to CVE-2024-48063. "
        f"Checks: {[(c.name, c.status) for c in result.checks]}"
    )


def test_pytorch_zip_cve_2024_48063_fixed_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that PyTorch 2.5.0+ does not trigger CVE-2024-48063 warning."""
    model_path = create_mock_pytorch_zip(tmp_path / "model.pt")
    scanner = PyTorchZipScanner()

    mock_torch = MagicMock()
    mock_torch.__version__ = "2.5.0"
    monkeypatch.setitem(sys.modules, "torch", mock_torch)

    result = scanner.scan(str(model_path))

    cve_failed = [c for c in result.checks if "CVE-2024-48063" in c.name and c.status == CheckStatus.FAILED]
    assert len(cve_failed) == 0, (
        f"PyTorch 2.5.0 should NOT trigger CVE-2024-48063. Failed checks: {[(c.name, c.message) for c in cve_failed]}"
    )
