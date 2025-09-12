"""Tests for the metadata extractor functionality."""

import json
import os
import struct
import tempfile
from pathlib import Path

from modelaudit.metadata_extractor import ModelMetadataExtractor


class TestModelMetadataExtractor:
    """Test the ModelMetadataExtractor class."""

    def test_extract_metadata_unknown_format(self):
        """Test metadata extraction with unknown file format."""
        extractor = ModelMetadataExtractor()

        with tempfile.NamedTemporaryFile(suffix=".unknown") as tmp:
            tmp.write(b"some random data")
            tmp.flush()

            metadata = extractor.extract(tmp.name)

            assert metadata["format"] == "unknown"
            assert "error" in metadata
            assert metadata["file"] == Path(tmp.name).name

    def test_extract_metadata_basic(self):
        """Test basic metadata extraction functionality."""
        extractor = ModelMetadataExtractor()

        # Create a simple safetensors file
        header = {"tensor1": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}
        header_json = json.dumps(header).encode("utf-8")
        header_len = len(header_json)

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
            tmp.write(struct.pack("<Q", header_len))
            tmp.write(header_json)
            tmp.write(b"\x00" * 16)  # Dummy tensor data
            tmp.flush()

            try:
                metadata = extractor.extract(tmp.name)

                assert metadata["format"] == "safetensors"
                assert metadata["file_size"] > 0
                assert metadata["tensor_count"] == 1
                assert metadata["total_parameters"] == 4
                assert "tensors" in metadata

            finally:
                os.unlink(tmp.name)

    def test_extract_directory_metadata(self):
        """Test directory metadata extraction."""
        extractor = ModelMetadataExtractor()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple test files
            safetensors_file = os.path.join(tmpdir, "model.safetensors")
            pkl_file = os.path.join(tmpdir, "model.pkl")

            # Create safetensors file
            header = {"test": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
            header_json = json.dumps(header).encode("utf-8")
            with open(safetensors_file, "wb") as f:
                f.write(struct.pack("<Q", len(header_json)))
                f.write(header_json)
                f.write(b"\x00\x00\x00\x00")

            # Create pickle file (empty for simplicity)
            with open(pkl_file, "wb") as f:
                import pickle

                pickle.dump({"test": "data"}, f)

            metadata = extractor.extract(tmpdir)

            assert "directory" in metadata
            assert metadata["directory"] == tmpdir
            assert metadata["summary"]["total_files"] >= 2
            assert "safetensors" in metadata["summary"]["formats"]
            assert "pickle" in metadata["summary"]["formats"]

    def test_security_only_filter(self):
        """Test security-only metadata filtering."""
        extractor = ModelMetadataExtractor()

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as tmp:
            header = {
                "tensor1": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                "__metadata__": {"framework": "test", "version": "1.0"},
            }
            header_json = json.dumps(header).encode("utf-8")
            tmp.write(struct.pack("<Q", len(header_json)))
            tmp.write(header_json)
            tmp.write(b"\x00\x00\x00\x00")
            tmp.flush()

            try:
                # Test with security_only=True
                metadata = extractor.extract(tmp.name, security_only=True)

                # Should contain basic info
                assert "file" in metadata
                assert "format" in metadata
                assert "file_size" in metadata

                # Should contain custom metadata (potentially security relevant)
                if "custom_metadata" in metadata:
                    assert metadata["custom_metadata"]["framework"] == "test"

            finally:
                os.unlink(tmp.name)

    def test_format_table_single_file(self):
        """Test table formatting for single file."""
        from modelaudit.cli import _format_metadata_table

        metadata = {
            "file": "test.safetensors",
            "format": "safetensors",
            "file_size": 1024,
            "tensor_count": 2,
            "custom_metadata": {"framework": "pytorch"},
        }

        output = _format_metadata_table(metadata)

        assert "File: test.safetensors" in output
        assert "Format: safetensors" in output
        assert "Size: 1,024 bytes" in output
        assert "Tensor Count: 2" in output
        assert "framework: pytorch" in output

    def test_format_table_directory(self):
        """Test table formatting for directory."""
        from modelaudit.cli import _format_metadata_table

        metadata = {
            "directory": "/test/path",
            "summary": {"total_files": 3, "formats": {"safetensors": 2, "pickle": 1}},
            "files": [
                {"file": "model1.safetensors", "format": "safetensors"},
                {"file": "model2.pkl", "format": "pickle"},
            ],
        }

        output = _format_metadata_table(metadata)

        assert "Directory: /test/path" in output
        assert "Total Files: 3" in output
        assert "safetensors: 2" in output
        assert "pickle: 1" in output
        assert "model1.safetensors (safetensors)" in output
        assert "model2.pkl (pickle)" in output
