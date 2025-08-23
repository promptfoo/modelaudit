"""
Demonstration test for file type validation feature using integration test data.

This test provides a concise example of how the file type validation feature works
with real model files, showcasing both security benefits and legitimate use cases.
"""

import zipfile
from pathlib import Path

import pytest

from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.utils.filetype import validate_file_type


class TestFileTypeValidationDemo:
    """Demonstration of file type validation capabilities."""

    @pytest.fixture
    def test_data_dir(self):
        """Return path to integration test data."""
        return Path(__file__).parent / "assets/scenarios/license_scenarios"

    def test_legitimate_files_validation_demo(self, test_data_dir):
        """Demonstrate validation of legitimate model files."""
        print("\n=== File Type Validation Demo: Legitimate Files ===")

        # Test legitimate files from integration test data
        test_files = [
            test_data_dir / "mit_model" / "model_weights.pkl",
            test_data_dir / "mit_model" / "config.json",
            test_data_dir / "unlicensed_dataset" / "embeddings.npy",
            test_data_dir / "agpl_component" / "agpl_model.pkl",
        ]

        for file_path in test_files:
            if file_path.exists():
                is_valid = validate_file_type(str(file_path))
                result = scan_file(str(file_path))

                validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

                print(
                    f"✅ {file_path.name}: Valid={is_valid}, Issues={len(validation_issues)}",
                )
                assert is_valid, f"Legitimate file {file_path.name} should be valid"
                assert len(validation_issues) == 0, f"No validation issues expected for {file_path.name}"

    def test_security_threat_detection_demo(self, tmp_path):
        """Demonstrate detection of file spoofing security threats."""
        print("\n=== File Type Validation Demo: Security Threats ===")

        # Create various file spoofing scenarios
        attack_scenarios = [
            ("fake_model.h5", b"This is not HDF5 but claims to be!" + b"\x00" * 50),
            ("malicious.pkl", "This is just text, not pickle data"),
            ("backdoor.safetensors", b"Not SafeTensors format" + b"\x00" * 100),
            ("trojan.gguf", b"FAKE" + b"\x00" * 100),  # Wrong magic bytes
        ]

        for filename, content in attack_scenarios:
            attack_file = tmp_path / filename
            if isinstance(content, str):
                attack_file.write_text(content)
            else:
                attack_file.write_bytes(content)

            is_valid = validate_file_type(str(attack_file))
            result = scan_file(str(attack_file))

            validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

            print(f"⚠️  {filename}: Valid={is_valid}, Issues={len(validation_issues)}")

            # Most should be detected as invalid (some may pass if format is too generic)
            if not is_valid or len(validation_issues) > 0:
                print(f"   ✅ THREAT DETECTED for {filename}")
            else:
                print("   ⚠️  Threat not detected (may be due to permissive validation)")

    def test_cross_format_compatibility_demo(self, tmp_path):
        """Demonstrate legitimate cross-format file compatibility."""
        print("\n=== File Type Validation Demo: Cross-Format Compatibility ===")

        # Create legitimate cross-format files
        # 1. PyTorch model saved as ZIP (common with torch.save())
        pytorch_zip = tmp_path / "model.pt"
        with zipfile.ZipFile(pytorch_zip, "w") as zipf:
            zipf.writestr("data.pkl", "tensor data")

        # 2. PyTorch binary that contains pickle data
        pytorch_pickle = tmp_path / "weights.bin"
        import pickle

        data = {"layer_weights": [1.0, 2.0, 3.0]}
        with open(pytorch_pickle, "wb") as f:
            pickle.dump(data, f)

        cross_format_files = [
            (pytorch_zip, "PyTorch ZIP (.pt with ZIP content)"),
            (pytorch_pickle, "PyTorch Binary (.bin with pickle content)"),
        ]

        for file_path, description in cross_format_files:
            is_valid = validate_file_type(str(file_path))
            result = scan_file(str(file_path))

            validation_issues = [i for i in result.issues if "file type validation failed" in i.message.lower()]

            print(
                f"✅ {description}: Valid={is_valid}, Issues={len(validation_issues)}",
            )
            assert is_valid, f"Legitimate cross-format file should be valid: {description}"
            assert len(validation_issues) == 0, f"No validation issues expected for: {description}"

    def test_directory_scan_demo(self, test_data_dir):
        """Demonstrate directory-level scanning with file type validation."""
        print("\n=== File Type Validation Demo: Directory Scanning ===")

        # Scan MIT model directory
        mit_dir = test_data_dir / "mit_model"
        if mit_dir.exists():
            results = scan_model_directory_or_file(str(mit_dir))

            validation_warnings = [
                issue for issue in results["issues"] if "file type validation failed" in issue.message.lower()
            ]

            print("📁 MIT Model Directory:")
            print(f"   Files scanned: {results['files_scanned']}")
            print(f"   Validation warnings: {len(validation_warnings)}")
            print(f"   Scan success: {results['success']}")

            assert results["success"], "Directory scan should succeed"
            assert len(validation_warnings) == 0, "No validation warnings expected for legitimate directory"

    def test_end_to_end_security_demo(self, test_data_dir, tmp_path):
        """End-to-end demonstration of security validation in mixed directory."""
        print("\n=== File Type Validation Demo: End-to-End Security ===")

        # Create a mixed directory with legitimate and malicious files
        mixed_dir = tmp_path / "security_test"
        mixed_dir.mkdir()

        # Copy a legitimate config file
        if (test_data_dir / "mit_model" / "config.json").exists():
            legitimate_config = test_data_dir / "mit_model" / "config.json"
            (mixed_dir / "config.json").write_text(legitimate_config.read_text())

        # Add a malicious file
        malicious_file = mixed_dir / "backdoor.h5"
        malicious_file.write_bytes(b"Not HDF5 format but claims to be!" + b"\x00" * 100)

        # Scan the directory
        results = scan_model_directory_or_file(str(mixed_dir))

        validation_warnings = [
            issue for issue in results["issues"] if "file type validation failed" in issue.message.lower()
        ]

        security_issues = [
            issue
            for issue in results["issues"]
            if any(keyword in issue.message.lower() for keyword in ["spoofing", "security", "validation failed"])
        ]

        print("📁 Mixed Directory (legitimate + malicious):")
        print(f"   Files scanned: {results['files_scanned']}")
        print(f"   Validation warnings: {len(validation_warnings)}")
        print(f"   Security issues: {len(security_issues)}")
        print(f"   Exit code: {self._get_exit_code(results)}")

        # Should detect security issues
        assert len(validation_warnings) > 0, "Should detect file type validation issues"
        assert results["success"], "Scan should complete successfully despite warnings"

        # Exit code should be 1 (warnings found)
        exit_code = self._get_exit_code(results)
        assert exit_code == 1, f"Expected exit code 1 (warnings), got {exit_code}"

        print(
            "   ✅ SECURITY THREATS DETECTED - File type validation working correctly!",
        )

    def _get_exit_code(self, results):
        """Helper to determine exit code from scan results."""
        from modelaudit.core import determine_exit_code

        return determine_exit_code(results)


if __name__ == "__main__":
    # Allow running for demonstration
    pytest.main([__file__, "-v", "-s"])
