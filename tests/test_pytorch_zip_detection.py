"""Test PyTorch ZIP scanner's ability to detect and scan .bin files."""

import io
import pickle
import zipfile

import pytest

# Skip if torch is not available before importing it
pytest.importorskip("torch")

import torch

from modelaudit.core import scan_file
from modelaudit.scanners.base import IssueSeverity
from modelaudit.utils.filetype import detect_file_format


class TestPyTorchZipDetection:
    """Test PyTorch ZIP file detection and scanning."""

    def test_detect_zip_bin_file(self, tmp_path):
        """Test that .bin files with ZIP format are detected correctly."""
        # Create a simple PyTorch model
        model_data = {"weights": torch.tensor([1.0, 2.0, 3.0])}

        # Save as .bin file using torch.save (creates a ZIP)
        bin_file = tmp_path / "pytorch_model.bin"
        torch.save(model_data, bin_file)

        # Verify file format detection
        format_type = detect_file_format(str(bin_file))
        assert format_type == "zip", f"Expected 'zip' but got '{format_type}'"

        # Verify the file can be scanned
        result = scan_file(str(bin_file))
        assert result is not None
        assert result.scanner_name == "pytorch_zip"
        assert result.bytes_scanned > 0

    def test_scan_malicious_bin_file(self, tmp_path):
        """Test detection of malicious code in .bin PyTorch files."""

        # Create a malicious pickle payload
        class MaliciousClass:
            def __reduce__(self):
                import os

                return (os.system, ("echo pwned",))

        # Create a ZIP file with the malicious pickle
        bin_file = tmp_path / "malicious_model.bin"
        with zipfile.ZipFile(bin_file, "w") as zf:
            # PyTorch models typically have data.pkl in archive/ directory
            pickle_data = io.BytesIO()
            pickle.dump({"model": MaliciousClass()}, pickle_data)
            zf.writestr("archive/data.pkl", pickle_data.getvalue())

        # Scan the file
        result = scan_file(str(bin_file))

        # Should detect the malicious pattern
        assert result.scanner_name == "pytorch_zip"
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues), (
            f"Expected CRITICAL issue but got: {[i.message for i in result.issues]}"
        )

    def test_scan_safe_bin_file(self, tmp_path):
        """Test that safe .bin files don't trigger false positives."""
        # Create a safe PyTorch model
        model_data = {
            "weights": torch.randn(10, 10),
            "bias": torch.randn(10),
            "config": {"layers": 3, "hidden_size": 10},
        }

        # Save as .bin file
        bin_file = tmp_path / "safe_model.bin"
        torch.save(model_data, bin_file)

        # Scan the file
        result = scan_file(str(bin_file))

        # Should not have critical issues
        critical_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
        assert len(critical_issues) == 0, f"Unexpected critical issues: {[i.message for i in critical_issues]}"

    def test_scan_bin_with_multiple_pickles(self, tmp_path):
        """Test scanning .bin files with multiple pickle files inside."""
        # Create a ZIP with multiple pickle files
        bin_file = tmp_path / "multi_pickle.bin"
        with zipfile.ZipFile(bin_file, "w") as zf:
            # Add multiple pickle files
            safe_data = {"weights": [1, 2, 3]}
            pickle_data = pickle.dumps(safe_data)
            zf.writestr("data.pkl", pickle_data)
            zf.writestr("archive/data.pkl", pickle_data)
            zf.writestr("model.pkl", pickle_data)

        # Scan the file
        result = scan_file(str(bin_file))

        # Should scan all pickle files
        assert result.scanner_name == "pytorch_zip"
        assert "pickle_files" in result.metadata
        assert len(result.metadata["pickle_files"]) >= 3

    def test_scan_bin_without_pkl_extension(self, tmp_path):
        """Test scanning .bin files where pickle data doesn't have .pkl extension."""
        # Create a ZIP with pickle data in non-.pkl files
        bin_file = tmp_path / "no_pkl_ext.bin"
        with zipfile.ZipFile(bin_file, "w") as zf:
            # PyTorch sometimes uses files without .pkl extension
            model_data = {"tensor": torch.tensor([1.0, 2.0])}
            pickle_data = pickle.dumps(model_data)

            # Add pickle data with various names
            zf.writestr("data", pickle_data)  # No extension
            zf.writestr("archive/data", pickle_data)
            zf.writestr("archive/constants", pickle_data)

        # Scan the file
        result = scan_file(str(bin_file))

        # Should still detect and scan the pickle data
        assert result.scanner_name == "pytorch_zip"
        assert result.bytes_scanned > 0

    def test_bin_file_with_exec_pattern(self, tmp_path):
        """Test detection of exec patterns in .bin files."""
        # Create a ZIP with exec pattern
        bin_file = tmp_path / "exec_model.bin"
        with zipfile.ZipFile(bin_file, "w") as zf:
            # Create pickle with exec pattern in the data
            malicious_data = {"code": "exec('import os; os.system(\"ls\")')", "weights": [1, 2, 3]}
            pickle_data = pickle.dumps(malicious_data)
            zf.writestr("archive/data.pkl", pickle_data)

        # Scan the file
        result = scan_file(str(bin_file))

        # Should detect exec pattern
        assert any("exec" in issue.message.lower() for issue in result.issues), (
            f"Expected 'exec' in issues but got: {[i.message for i in result.issues]}"
        )


class TestPyTorchBinaryDetection:
    """Test that non-ZIP .bin files are handled correctly."""

    def test_non_zip_bin_file(self, tmp_path):
        """Test that non-ZIP .bin files are not handled by PyTorchZipScanner."""
        # Create a raw binary file (not ZIP)
        bin_file = tmp_path / "raw_binary.bin"
        bin_file.write_bytes(b"\x00\x01\x02\x03" * 100)

        # Verify file format detection
        format_type = detect_file_format(str(bin_file))
        assert format_type == "pytorch_binary", f"Expected 'pytorch_binary' but got '{format_type}'"

        # Verify correct scanner is used
        result = scan_file(str(bin_file))
        assert result.scanner_name == "pytorch_binary"

    def test_pickle_bin_file(self, tmp_path):
        """Test that pickle .bin files are detected correctly."""
        # Create a .bin file that's actually a pickle (not ZIP)
        bin_file = tmp_path / "pickle.bin"
        data = {"weights": [1, 2, 3]}
        with open(bin_file, "wb") as f:
            pickle.dump(data, f)

        # Verify file format detection
        format_type = detect_file_format(str(bin_file))
        assert format_type == "pickle", f"Expected 'pickle' but got '{format_type}'"

        # Verify correct scanner is used
        result = scan_file(str(bin_file))
        assert result.scanner_name == "pickle"
