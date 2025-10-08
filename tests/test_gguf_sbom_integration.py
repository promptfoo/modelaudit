"""Integration tests for GGUF SBOM generation."""

import json
import tempfile
from pathlib import Path

from modelaudit.core import scan_model_directory_or_file
from modelaudit.integrations.sbom_generator import generate_sbom_pydantic


def create_test_gguf(file_path: Path) -> None:
    """Create a minimal test GGUF file."""
    import struct

    with open(file_path, "wb") as f:
        # Header
        f.write(b"GGUF")
        f.write(struct.pack("<I", 3))  # version
        f.write(struct.pack("<Q", 1))  # tensor count
        f.write(struct.pack("<Q", 2))  # kv count

        # Metadata - first key-value pair
        kv_key1 = b"general.name"
        kv_value1 = b"test_model"
        f.write(struct.pack("<Q", len(kv_key1)))
        f.write(kv_key1)
        f.write(struct.pack("<I", 8))  # value type (string)
        f.write(struct.pack("<Q", len(kv_value1)))
        f.write(kv_value1)

        # Metadata - second key-value pair
        kv_key2 = b"general.alignment"
        f.write(struct.pack("<Q", len(kv_key2)))
        f.write(kv_key2)
        f.write(struct.pack("<I", 4))  # value type (UINT32)
        f.write(struct.pack("<I", 32))  # alignment value

        # Align to 32 bytes
        current = f.tell()
        pad = (32 - (current % 32)) % 32
        if pad:
            f.write(b"\0" * pad)

        # Tensor info
        name = b"weight"
        f.write(struct.pack("<Q", len(name)))
        f.write(name)
        f.write(struct.pack("<I", 2))  # nd = 2 dimensions
        f.write(struct.pack("<Q", 4))  # dim 1
        f.write(struct.pack("<Q", 4))  # dim 2
        f.write(struct.pack("<I", 0))  # type (F32)
        f.write(struct.pack("<Q", f.tell() + 100))  # offset

        # Write some dummy tensor data
        f.write(b"\x00" * 64)  # 16 float32 values (4x4)


class TestGgufSbomIntegration:
    """Integration tests for GGUF SBOM generation."""

    def test_gguf_sbom_generation_success(self):
        """Test that GGUF files can generate valid SBOMs without errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gguf_file = Path(tmpdir) / "test.gguf"
            create_test_gguf(gguf_file)

            # Scan the GGUF file
            results = scan_model_directory_or_file(str(gguf_file), timeout=30, max_total_size=100 * 1024 * 1024)

            # Ensure scan succeeded
            assert results is not None
            assert len(results.assets) == 1
            assert results.assets[0].type == "gguf"

            # Generate SBOM - this should not raise any ValidationErrors
            sbom_json = generate_sbom_pydantic([str(gguf_file)], results)

            # Parse and validate SBOM structure
            sbom_data = json.loads(sbom_json)

            # Check required CycloneDX v1.6 fields
            assert sbom_data["bomFormat"] == "CycloneDX"
            assert sbom_data["specVersion"] == "1.6"
            assert "components" in sbom_data
            assert len(sbom_data["components"]) == 1

            # Check component structure - v1.6 should use machine-learning-model type for GGUF
            component = sbom_data["components"][0]
            assert component["name"] == "test.gguf"
            assert component["type"] == "machine-learning-model"
            assert "hashes" in component
            assert len(component["hashes"]) == 1
            assert component["hashes"][0]["alg"] == "SHA-256"

            # Check properties - v1.6 should include enhanced ML and security properties
            properties = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
            assert "size" in properties
            assert "risk_score" in properties
            assert int(properties["risk_score"]) >= 0

            # v1.6 enhanced properties
            assert "security:scanned" in properties
            assert properties["security:scanned"] == "true"
            assert "security:scanner" in properties
            assert properties["security:scanner"] == "ModelAudit"

    def test_gguf_sbom_tensor_metadata_handling(self):
        """Test that GGUF tensor metadata is properly handled in assets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gguf_file = Path(tmpdir) / "tensor_test.gguf"
            create_test_gguf(gguf_file)

            # Scan the file
            results = scan_model_directory_or_file(str(gguf_file), timeout=30, max_total_size=100 * 1024 * 1024)

            # Check that assets were created without validation errors
            assert len(results.assets) == 1
            asset = results.assets[0]
            assert asset.type == "gguf"

            # Check that tensor metadata exists and is in the correct format
            assert asset.tensors is not None
            assert isinstance(asset.tensors, list)

            # All tensors should be strings (tensor names), not dictionaries
            for tensor in asset.tensors:
                assert isinstance(tensor, str), f"Expected string tensor name, got {type(tensor)}: {tensor}"

            # Should have at least one tensor (our test file has one)
            assert len(asset.tensors) > 0
            assert "weight" in asset.tensors

    def test_gguf_multiple_tensors_sbom(self):
        """Test GGUF SBOM with multiple tensors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gguf_file = Path(tmpdir) / "multi_tensor.gguf"

            # Create a GGUF with multiple tensors
            import struct

            with open(gguf_file, "wb") as f:
                # Header
                f.write(b"GGUF")
                f.write(struct.pack("<I", 3))  # version
                f.write(struct.pack("<Q", 3))  # tensor count - 3 tensors
                f.write(struct.pack("<Q", 1))  # kv count

                # Metadata
                kv_key = b"general.name"
                kv_value = b"multi_tensor_model"
                f.write(struct.pack("<Q", len(kv_key)))
                f.write(kv_key)
                f.write(struct.pack("<I", 8))  # value type (string)
                f.write(struct.pack("<Q", len(kv_value)))
                f.write(kv_value)

                # Align to 32 bytes
                current = f.tell()
                pad = (32 - (current % 32)) % 32
                if pad:
                    f.write(b"\0" * pad)

                # Three tensors
                tensor_names = [b"encoder.weight", b"decoder.weight", b"output.bias"]
                for name in tensor_names:
                    f.write(struct.pack("<Q", len(name)))
                    f.write(name)
                    f.write(struct.pack("<I", 1))  # nd = 1 dimension
                    f.write(struct.pack("<Q", 10))  # dim size
                    f.write(struct.pack("<I", 0))  # type (F32)
                    f.write(struct.pack("<Q", f.tell() + 200))  # offset

                # Write dummy data
                f.write(b"\x00" * 120)  # 3 tensors x 10 elements x 4 bytes

            results = scan_model_directory_or_file(str(gguf_file), timeout=30, max_total_size=100 * 1024 * 1024)

            # Verify asset creation
            assert len(results.assets) == 1
            asset = results.assets[0]
            assert asset.tensors is not None and len(asset.tensors) == 3

            expected_names = ["encoder.weight", "decoder.weight", "output.bias"]
            assert asset.tensors is not None and all(name in asset.tensors for name in expected_names)

            # Generate SBOM successfully
            sbom_json = generate_sbom_pydantic([str(gguf_file)], results)
            sbom_data = json.loads(sbom_json)
            assert len(sbom_data["components"]) == 1

    def test_gguf_sbom_with_security_issues(self):
        """Test that GGUF SBOM generation works even when security issues are found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gguf_file = Path(tmpdir) / "security_test.gguf"
            create_test_gguf(gguf_file)

            results = scan_model_directory_or_file(str(gguf_file), timeout=30, max_total_size=100 * 1024 * 1024)

            # The test file may have security issues (tensor size mismatch)
            # but SBOM generation should still work
            sbom_json = generate_sbom_pydantic([str(gguf_file)], results)
            sbom_data = json.loads(sbom_json)

            assert len(sbom_data["components"]) == 1
            component = sbom_data["components"][0]

            # Risk score should reflect any security issues found
            properties = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
            risk_score = int(properties.get("risk_score", "0"))

            # Risk score may be > 0 due to security issues, but SBOM should be valid
            assert risk_score >= 0
            assert risk_score <= 10
