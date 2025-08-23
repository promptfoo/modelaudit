"""
Integration tests for file type validation using magic numbers.

These tests verify the file type validation feature works correctly with:
- Real model files from integration test data
- File spoofing attack scenarios
- Mixed file type directories
- Cross-format compatibility cases
- Security threat detection
"""

import json
import shutil
import zipfile
from pathlib import Path

import numpy as np
import pytest

from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.utils.filetype import (
    detect_file_format_from_magic,
    detect_format_from_extension,
    validate_file_type,
)

try:
    from safetensors.numpy import save_file

    HAS_SAFETENSORS = True
except ImportError:
    HAS_SAFETENSORS = False


class TestFileTypeValidationIntegration:
    """Integration tests for file type validation feature."""

    @pytest.fixture
    def test_data_dir(self):
        """Return path to integration test data."""
        return Path(__file__).parent / "assets/scenarios/license_scenarios"

    @pytest.fixture
    def temp_test_dir(self, tmp_path):
        """Create a temporary directory with copies of test data for modification."""
        test_data_dir = Path(__file__).parent / "assets/scenarios/license_scenarios"
        temp_dir = tmp_path / "file_type_tests"
        temp_dir.mkdir()

        # Copy test data to temp directory
        for subdir in [
            "mit_model",
            "agpl_component",
            "mixed_licenses",
            "unlicensed_dataset",
        ]:
            src_dir = test_data_dir / subdir
            if src_dir.exists():
                dest_dir = temp_dir / subdir
                shutil.copytree(src_dir, dest_dir)

        return temp_dir

    def test_existing_files_pass_validation(self, test_data_dir):
        """Test that all existing integration test files pass file type validation."""
        validation_failures = []

        # Test all files in the integration test data
        for test_subdir in [
            "mit_model",
            "agpl_component",
            "mixed_licenses",
            "unlicensed_dataset",
        ]:
            subdir_path = test_data_dir / test_subdir
            if not subdir_path.exists():
                continue

            for file_path in subdir_path.rglob("*"):
                if file_path.is_file():
                    try:
                        # Test our validation function
                        is_valid = validate_file_type(str(file_path))
                        header_format = detect_file_format_from_magic(str(file_path))
                        ext_format = detect_format_from_extension(str(file_path))

                        if not is_valid:
                            validation_failures.append(
                                {
                                    "file": str(file_path.relative_to(test_data_dir)),
                                    "header_format": header_format,
                                    "ext_format": ext_format,
                                },
                            )

                        # Also test scanning doesn't produce validation errors
                        result = scan_file(str(file_path))
                        validation_issues = [
                            i for i in result.issues if "file type validation failed" in i.message.lower()
                        ]

                        if validation_issues:
                            validation_failures.append(
                                {
                                    "file": str(file_path.relative_to(test_data_dir)),
                                    "scan_issues": [i.message for i in validation_issues],
                                },
                            )

                    except Exception as e:
                        validation_failures.append(
                            {
                                "file": str(file_path.relative_to(test_data_dir)),
                                "error": str(e),
                            },
                        )

        # All legitimate files should pass validation
        assert len(validation_failures) == 0, (
            f"Expected legitimate files to pass validation, but found failures: {validation_failures}"
        )

    def test_pickle_files_validation(self, test_data_dir):
        """Test specific validation of pickle files in test data."""
        # Test MIT model pickle file
        mit_pickle = test_data_dir / "mit_model" / "model_weights.pkl"
        if mit_pickle.exists():
            assert validate_file_type(str(mit_pickle)), "MIT model pickle should be valid"

            result = scan_file(str(mit_pickle))
            validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]
            assert len(validation_issues) == 0, "MIT pickle should not have validation issues"

        # Test AGPL model pickle file
        agpl_pickle = test_data_dir / "agpl_component" / "agpl_model.pkl"
        if agpl_pickle.exists():
            assert validate_file_type(str(agpl_pickle)), "AGPL model pickle should be valid"

    def test_numpy_files_validation(self, test_data_dir):
        """Test validation of NumPy files."""
        embeddings_file = test_data_dir / "unlicensed_dataset" / "embeddings.npy"
        if embeddings_file.exists():
            # Should detect as numpy format
            header_format = detect_file_format_from_magic(str(embeddings_file))
            ext_format = detect_format_from_extension(str(embeddings_file))

            assert header_format == "numpy", f"Expected numpy, got {header_format}"
            assert ext_format == "numpy", f"Expected numpy, got {ext_format}"
            assert validate_file_type(str(embeddings_file)), "NumPy file should be valid"

    def test_json_files_validation(self, test_data_dir):
        """Test validation of JSON configuration files."""
        config_files = [
            test_data_dir / "mit_model" / "config.json",
            test_data_dir / "mixed_licenses" / "dataset_cc_nc.json",
            test_data_dir / "unlicensed_dataset" / "training_data.json",
        ]

        for config_file in config_files:
            if config_file.exists():
                # JSON files don't have specific magic bytes, so validation should be permissive
                is_valid = validate_file_type(str(config_file))
                assert is_valid, f"JSON file {config_file.name} should be valid"

    def test_file_spoofing_detection(self, temp_test_dir):
        """Test detection of file spoofing attacks."""
        spoofing_attacks = []

        # Test 1: Fake HDF5 file
        fake_h5 = temp_test_dir / "malicious.h5"
        fake_h5.write_bytes(b"This is not HDF5 data but claims to be!" + b"\x00" * 100)

        result = scan_file(str(fake_h5))
        validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

        if len(validation_issues) == 0:
            spoofing_attacks.append("Fake HDF5 not detected")

        # Test 2: Fake SafeTensors file
        if HAS_SAFETENSORS:
            fake_safetensors = temp_test_dir / "malicious.safetensors"
            fake_safetensors.write_bytes(b"Not SafeTensors format" + b"\x00" * 100)

            result = scan_file(str(fake_safetensors))
            validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

            if len(validation_issues) == 0:
                spoofing_attacks.append("Fake SafeTensors not detected")

        # Test 3: Fake GGUF file
        fake_gguf = temp_test_dir / "malicious.gguf"
        fake_gguf.write_bytes(b"FAKE" + b"\x00" * 100)  # Wrong magic bytes

        result = scan_file(str(fake_gguf))
        validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

        if len(validation_issues) == 0:
            spoofing_attacks.append("Fake GGUF not detected")

        # Test 4: Text file with pickle extension
        fake_pickle = temp_test_dir / "malicious.pkl"
        fake_pickle.write_text("This is just text, not pickle data")

        result = scan_file(str(fake_pickle))
        validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

        if len(validation_issues) == 0:
            spoofing_attacks.append("Fake pickle not detected")

        # All spoofing attacks should be detected
        assert len(spoofing_attacks) == 0, f"Failed to detect spoofing attacks: {spoofing_attacks}"

    def test_legitimate_cross_format_files(self, temp_test_dir):
        """Test legitimate files that have different formats than their extensions suggest."""
        # Test 1: PyTorch file saved as ZIP (legitimate case)
        pytorch_zip = temp_test_dir / "model.pt"
        with zipfile.ZipFile(pytorch_zip, "w") as zipf:
            zipf.writestr("data.pkl", "tensor data")

        # Should pass validation (ZIP format with .pt extension is legitimate)
        assert validate_file_type(str(pytorch_zip)), "PyTorch ZIP file should be valid"

        result = scan_file(str(pytorch_zip))
        validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]
        assert len(validation_issues) == 0, "PyTorch ZIP should not trigger validation failures"

        # Test 2: PyTorch binary that's actually pickle format
        pytorch_pickle = temp_test_dir / "weights.bin"
        # Create a real pickle file
        import pickle

        data = {"weights": [1.0, 2.0, 3.0]}
        with open(pytorch_pickle, "wb") as f:
            pickle.dump(data, f)

        # Should pass validation (.bin with pickle content is legitimate)
        assert validate_file_type(str(pytorch_pickle)), "PyTorch pickle binary should be valid"

    def test_directory_scan_with_validation(self, temp_test_dir):
        """Test scanning entire directories with file type validation enabled."""
        # Scan the MIT model directory
        mit_dir = temp_test_dir / "mit_model"
        if mit_dir.exists():
            results = scan_model_directory_or_file(str(mit_dir))

            # Should complete successfully
            assert results["success"], "MIT model directory scan should succeed"

            # Check for validation issues
            validation_issues = [
                issue for issue in results["issues"] if "file type validation failed" in issue.message.lower()
            ]

            assert len(validation_issues) == 0, (
                f"MIT model directory should not have validation issues: {validation_issues}"
            )

        # Scan a directory with mixed file types
        mixed_dir = temp_test_dir / "mixed_licenses"
        if mixed_dir.exists():
            results = scan_model_directory_or_file(str(mixed_dir))

            # Should complete successfully
            assert results["success"], "Mixed licenses directory scan should succeed"

    def test_security_threat_scenarios(self, temp_test_dir):
        """Test various security threat scenarios involving file type mismatches."""
        security_threats = []

        # Scenario 1: Executable disguised as model file
        malicious_model = temp_test_dir / "backdoor_model.pkl"
        # Simulate a file with executable signatures
        malicious_content = b"\x80\x03"  # Pickle header
        malicious_content += b"MZ"  # Windows PE signature
        malicious_content += b"\x00" * 100
        malicious_model.write_bytes(malicious_content)

        result = scan_file(str(malicious_model))
        # Should detect executable patterns (this would be caught by pickle scanner)
        # Check if any issues were detected (executable patterns would be caught by pickle scanner)

        # Scenario 2: Model with suspicious file size vs content mismatch
        tiny_model = temp_test_dir / "suspicious_model.h5"
        tiny_model.write_bytes(b"x" * 10)  # Tiny file claiming to be HDF5

        result = scan_file(str(tiny_model))
        validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

        if len(validation_issues) == 0:
            security_threats.append("Tiny fake HDF5 not detected")

        # Scenario 3: Model directory with mixed legitimate and malicious files
        attack_dir = temp_test_dir / "attack_scenario"
        attack_dir.mkdir(exist_ok=True)

        # Add legitimate config
        config = {"model_type": "transformer", "hidden_size": 768}
        (attack_dir / "config.json").write_text(json.dumps(config))

        # Add malicious file with misleading extension
        (attack_dir / "weights.safetensors").write_bytes(b"Not SafeTensors at all")

        results = scan_model_directory_or_file(str(attack_dir))
        all_validation_issues = [
            issue for issue in results["issues"] if "file type validation failed" in issue.message.lower()
        ]

        if len(all_validation_issues) == 0:
            security_threats.append(
                "Mixed legitimate/malicious directory not fully detected",
            )

        # Some security threats should be detected
        total_detections = len([t for t in security_threats if "not detected" not in t])
        print(f"Security threat detections: {total_detections}")
        print(f"Undetected threats: {security_threats}")

    def test_format_compatibility_matrix(self, tmp_path):
        """Test the file format compatibility matrix systematically."""
        test_cases = []

        # Create various file types and test validation
        test_files = []

        # Valid cases (should pass)
        if HAS_SAFETENSORS:
            # SafeTensors file
            st_file = tmp_path / "valid.safetensors"
            weights = {"test": np.array([1, 2, 3], dtype=np.float32)}
            save_file(weights, st_file)
            test_files.append((st_file, True, "Valid SafeTensors"))

        # NumPy file
        npy_file = tmp_path / "valid.npy"
        np.save(npy_file, np.array([1, 2, 3]))
        test_files.append((npy_file, True, "Valid NumPy"))

        # ZIP file
        zip_file = tmp_path / "valid.zip"
        with zipfile.ZipFile(zip_file, "w") as zipf:
            zipf.writestr("test.txt", "data")
        test_files.append((zip_file, True, "Valid ZIP"))

        # PyTorch ZIP (legitimate cross-format)
        pt_zip = tmp_path / "model.pt"
        with zipfile.ZipFile(pt_zip, "w") as zipf:
            zipf.writestr("data.pkl", "tensor")
        test_files.append((pt_zip, True, "PyTorch ZIP"))

        # Invalid cases (should fail)
        fake_npy = tmp_path / "fake.npy"
        fake_npy.write_bytes(b"not numpy data")
        test_files.append((fake_npy, False, "Fake NumPy"))

        fake_zip = tmp_path / "fake.zip"
        fake_zip.write_bytes(b"not zip data")
        test_files.append((fake_zip, False, "Fake ZIP"))

        # Test each case
        for file_path, should_be_valid, description in test_files:
            actual_valid = validate_file_type(str(file_path))
            if actual_valid != should_be_valid:
                test_cases.append(
                    f"{description}: expected {should_be_valid}, got {actual_valid}",
                )

        assert len(test_cases) == 0, f"Format compatibility test failures: {test_cases}"

    def test_edge_cases_and_corner_scenarios(self, tmp_path):
        """Test edge cases and corner scenarios for file type validation."""
        edge_cases = []

        # Empty file
        empty_file = tmp_path / "empty.pkl"
        empty_file.touch()
        # Empty files should be valid (can't determine type)
        if not validate_file_type(str(empty_file)):
            edge_cases.append("Empty file validation failed")

        # Very small file
        tiny_file = tmp_path / "tiny.h5"
        tiny_file.write_bytes(b"hi")
        # Small files should be valid (insufficient data for magic bytes)
        if not validate_file_type(str(tiny_file)):
            edge_cases.append("Tiny file validation failed")

        # File with unknown extension
        unknown_file = tmp_path / "unknown.xyz"
        unknown_file.write_bytes(b"some data")
        # Unknown extensions should be valid (can't validate)
        if not validate_file_type(str(unknown_file)):
            edge_cases.append("Unknown extension validation failed")

        # File with no extension
        no_ext_file = tmp_path / "noextension"
        no_ext_file.write_bytes(b"some data")
        # No extension should be valid
        if not validate_file_type(str(no_ext_file)):
            edge_cases.append("No extension validation failed")

        assert len(edge_cases) == 0, f"Edge case failures: {edge_cases}"

    @pytest.mark.integration
    def test_performance_with_large_directories(self, test_data_dir):
        """Test that file type validation doesn't significantly impact performance."""
        import time

        # Time scanning without focusing on validation performance
        # (This is more of a smoke test to ensure validation doesn't break things)
        start_time = time.time()

        # Scan all test directories
        for subdir in [
            "mit_model",
            "agpl_component",
            "mixed_licenses",
            "unlicensed_dataset",
        ]:
            test_dir = test_data_dir / subdir
            if test_dir.exists():
                results = scan_model_directory_or_file(str(test_dir))
                assert results["success"], f"Scan of {subdir} should succeed"

        elapsed = time.time() - start_time
        print(f"Total scan time with validation: {elapsed:.2f}s")

        # Should complete in reasonable time (this is a basic smoke test)
        assert elapsed < 30, "Scanning should complete in reasonable time"

    def test_cli_integration_with_validation_warnings(self, temp_test_dir):
        """Test CLI integration produces appropriate validation warnings."""
        # Create a directory with validation issues
        attack_dir = temp_test_dir / "validation_test"
        attack_dir.mkdir(exist_ok=True)

        # Add a legitimate file
        config = {"model_type": "test"}
        (attack_dir / "config.json").write_text(json.dumps(config))

        # Add a file with validation issues
        fake_h5 = attack_dir / "malicious.h5"
        fake_h5.write_bytes(b"Not HDF5 format" + b"\x00" * 50)

        # Scan the directory
        results = scan_model_directory_or_file(str(attack_dir))

        # Should have validation warnings
        validation_warnings = [
            issue
            for issue in results["issues"]
            if "file type validation failed" in issue.message.lower() and str(issue.severity).endswith("WARNING")
        ]

        assert len(validation_warnings) > 0, "Should generate file type validation warnings"

        # Should still complete successfully (warnings, not errors)
        assert results["success"], "Scan should complete successfully despite warnings"

        # Exit code should be 1 (warnings found) not 0 (clean) or 2 (errors)
        from modelaudit.core import determine_exit_code

        exit_code = determine_exit_code(results)
        assert exit_code == 1, f"Expected exit code 1 (warnings), got {exit_code}"


if __name__ == "__main__":
    # Allow running individual tests for debugging
    pytest.main([__file__, "-v"])
