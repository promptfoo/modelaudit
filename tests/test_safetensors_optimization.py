"""Test that SafeTensors files are not processed by WeightDistributionScanner for performance."""

import json
import os
import struct
import tempfile

import pytest

from modelaudit.scanners.safetensors_scanner import SafeTensorsScanner
from modelaudit.scanners.weight_distribution_scanner import WeightDistributionScanner


class TestSafeTensorsOptimization:
    """Test suite for SafeTensors performance optimization."""

    def create_minimal_safetensors(self, path: str) -> None:
        """Create a minimal valid SafeTensors file for testing."""
        # Create a minimal header with one small tensor
        header = {
            "test_tensor": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [0, 16],  # 4 floats * 4 bytes = 16 bytes
            },
            "__metadata__": {"format": "pt"},
        }

        header_bytes = json.dumps(header).encode("utf-8")
        header_len = len(header_bytes)

        with open(path, "wb") as f:
            # Write header length (8 bytes, little-endian)
            f.write(struct.pack("<Q", header_len))
            # Write header
            f.write(header_bytes)
            # Write dummy tensor data (4 float32 values)
            f.write(b"\x00" * 16)

    def test_weight_distribution_scanner_skips_safetensors(self):
        """Test that WeightDistributionScanner does not handle SafeTensors files."""
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
            try:
                self.create_minimal_safetensors(tmp.name)

                # WeightDistributionScanner should not handle SafeTensors
                scanner = WeightDistributionScanner()
                assert not scanner.can_handle(tmp.name), (
                    "WeightDistributionScanner should not handle .safetensors files"
                )
            finally:
                os.unlink(tmp.name)

    def test_safetensors_scanner_still_handles_safetensors(self):
        """Test that SafeTensorsScanner still handles SafeTensors files."""
        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
            try:
                self.create_minimal_safetensors(tmp.name)

                # SafeTensorsScanner should still handle SafeTensors
                scanner = SafeTensorsScanner()
                assert scanner.can_handle(tmp.name), "SafeTensorsScanner should handle .safetensors files"

                # Should be able to scan successfully
                result = scanner.scan(tmp.name)
                assert result.success, "Scan should be successful"
                assert not result.has_errors, "Scan should not have errors"
            finally:
                os.unlink(tmp.name)

    def test_safetensors_not_in_supported_extensions(self):
        """Test that .safetensors is not in WeightDistributionScanner's supported extensions."""
        scanner = WeightDistributionScanner()
        assert ".safetensors" not in scanner.supported_extensions, (
            ".safetensors should not be in WeightDistributionScanner's supported extensions"
        )

    def test_other_formats_still_handled(self):
        """Test that other model formats are still handled by WeightDistributionScanner."""
        scanner = WeightDistributionScanner()

        # These extensions should still be supported
        expected_extensions = [".pt", ".pth", ".h5", ".keras", ".hdf5", ".pb", ".onnx"]
        for ext in expected_extensions:
            assert ext in scanner.supported_extensions, f"{ext} should still be in supported extensions"

    def test_safetensors_with_different_case(self):
        """Test that SafeTensors files with different case extensions are also skipped."""
        scanner = WeightDistributionScanner()

        # Test various case combinations
        test_cases = [
            "model.safetensors",
            "model.SAFETENSORS",
            "model.SafeTensors",
            "model.saFeTenSors",
        ]

        for filename in test_cases:
            with tempfile.NamedTemporaryFile(suffix=filename[5:], delete=False) as tmp:
                try:
                    # Rename to get the exact filename we want
                    os.rename(tmp.name, filename)
                    self.create_minimal_safetensors(filename)

                    assert not scanner.can_handle(filename), f"WeightDistributionScanner should not handle {filename}"
                finally:
                    if os.path.exists(filename):
                        os.unlink(filename)

    @pytest.mark.parametrize("extension", [".pt", ".pth", ".onnx"])
    def test_non_safetensors_still_processed(self, extension):
        """Test that non-SafeTensors files are still processed by WeightDistributionScanner."""
        scanner = WeightDistributionScanner()

        with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as tmp:
            try:
                # Write some dummy data
                tmp.write(b"dummy model data")
                tmp.flush()

                # Check if scanner would try to handle it (based on extension)
                # Note: actual handling depends on having the right libraries installed
                ext = os.path.splitext(tmp.name)[1].lower()
                assert ext in scanner.supported_extensions, f"{extension} should be in supported extensions"
            finally:
                os.unlink(tmp.name)
