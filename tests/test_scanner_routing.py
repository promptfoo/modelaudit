"""
Test scanner routing for file type detection.
"""

import tempfile
import zipfile
from pathlib import Path

from modelaudit.scanners import get_scanner_for_file


class TestScannerRouting:
    """Test that files are routed to the correct scanner based on format detection."""

    def test_pt_zip_routing(self):
        """Test that ZIP-formatted .pt files go to PyTorchZipScanner, not FicklingPickleScanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a ZIP-based .pt file (like torch.save() creates)
            pt_file = Path(temp_dir) / "model.pt"

            with zipfile.ZipFile(pt_file, "w") as zf:
                zf.writestr("version", "3")
                zf.writestr("data.pkl", b"test pickle content")

            # Get scanner for the file
            scanner = get_scanner_for_file(str(pt_file))

            # Should be PyTorchZipScanner, not FicklingPickleScanner
            assert scanner is not None
            assert scanner.__class__.__name__ == "PyTorchZipScanner"

    def test_pth_zip_routing(self):
        """Test that ZIP-formatted .pth files go to PyTorchZipScanner, not FicklingPickleScanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a ZIP-based .pth file
            pth_file = Path(temp_dir) / "checkpoint.pth"

            with zipfile.ZipFile(pth_file, "w") as zf:
                zf.writestr("version", "3")
                zf.writestr("data.pkl", b"test checkpoint content")

            # Get scanner for the file
            scanner = get_scanner_for_file(str(pth_file))

            # Should be PyTorchZipScanner, not FicklingPickleScanner
            assert scanner is not None
            assert scanner.__class__.__name__ == "PyTorchZipScanner"

    def test_bin_zip_routing(self):
        """Test that ZIP-formatted .bin files go to PyTorchZipScanner, not FicklingPickleScanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a ZIP-based .bin file
            bin_file = Path(temp_dir) / "pytorch_model.bin"

            with zipfile.ZipFile(bin_file, "w") as zf:
                zf.writestr("version", "3")
                zf.writestr("data.pkl", b"test model content")

            # Get scanner for the file
            scanner = get_scanner_for_file(str(bin_file))

            # Should be PyTorchZipScanner, not FicklingPickleScanner
            assert scanner is not None
            assert scanner.__class__.__name__ == "PyTorchZipScanner"

    def test_pkl_file_routing(self):
        """Test that .pkl files go to FicklingPickleScanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a simple .pkl file
            pkl_file = Path(temp_dir) / "test.pkl"
            pkl_file.write_bytes(b"test pickle content")

            # Get scanner for the file
            scanner = get_scanner_for_file(str(pkl_file))

            # Should be FicklingPickleScanner (or fallback if fickling unavailable)
            assert scanner is not None
            # Scanner name should be "pickle" regardless of implementation
            assert hasattr(scanner, "name") and scanner.name == "pickle"

    def test_nonzip_pt_routing(self):
        """Test that non-ZIP .pt files fall back to FicklingPickleScanner."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a non-ZIP .pt file (raw pickle content)
            pt_file = Path(temp_dir) / "raw_pickle.pt"
            pt_file.write_bytes(b"test non-zip content")

            # Get scanner for the file
            scanner = get_scanner_for_file(str(pt_file))

            # Should be FicklingPickleScanner since it's not ZIP format
            assert scanner is not None
            # Should be pickle scanner (fickling or fallback)
            assert hasattr(scanner, "name") and scanner.name == "pickle"
