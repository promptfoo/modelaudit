import pickle
import sys
import unittest
from pathlib import Path

# Add the parent directory to sys.path to allow importing modelaudit
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modelaudit.scanners.base import IssueSeverity  # noqa: E402

# Import only what we need for the pickle scanner test
from modelaudit.scanners.pickle_scanner import PickleScanner  # noqa: E402
from tests.evil_pickle import EvilClass  # noqa: E402


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        # Path to evil.pickle sample
        self.evil_pickle_path = Path(__file__).parent / "evil.pickle"

        # Create the evil pickle if it doesn't exist
        if not self.evil_pickle_path.exists():
            evil_obj = EvilClass()
            with self.evil_pickle_path.open("wb") as f:
                pickle.dump(evil_obj, f)

    def test_scan_evil_pickle(self):
        """Test that the scanner can detect the malicious pickle
        created by evil_pickle.py"""
        scanner = PickleScanner()
        result = scanner.scan(str(self.evil_pickle_path))

        # Check that the scan completed successfully
        assert result.success

        # Check that issues were found
        assert result.has_errors

        # Print the found issues for debugging
        print(f"Found {len(result.issues)} issues:")
        for issue in result.issues:
            print(f"  - {issue.severity.name}: {issue.message}")

        # Check that specific issues were detected
        has_reduce_detection = False
        has_os_system_detection = False

        for issue in result.issues:
            if "REDUCE" in issue.message:
                has_reduce_detection = True
            if "posix.system" in issue.message or "os.system" in issue.message:
                has_os_system_detection = True

        assert has_reduce_detection, "Failed to detect REDUCE opcode"
        assert has_os_system_detection, (
            "Failed to detect os.system/posix.system reference"
        )

    def test_scan_nonexistent_file(self):
        """Scanner returns failure and error issue for missing file"""
        scanner = PickleScanner()
        result = scanner.scan("nonexistent_file.pkl")

        assert result.success is False
        assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)

    def test_scan_bin_file_with_suspicious_binary_content(self):
        """Test scanning .bin file with suspicious code patterns in binary data"""
        scanner = PickleScanner()

        # Create a temporary .bin file with pickle header + suspicious binary content
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add suspicious binary content
                suspicious_content = (
                    b"some_data" + b"import os" + b"more_data" + b"eval(" + b"end_data"
                )
                f.write(suspicious_content)
                f.flush()

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find suspicious patterns
                suspicious_issues = [
                    issue
                    for issue in result.issues
                    if "suspicious code pattern" in issue.message.lower()
                ]
                assert (
                    len(suspicious_issues) >= 2
                )  # Should find both "import os" and "eval("

                # Check metadata
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 0

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_with_executable_signatures(self):
        """Test scanning .bin file with executable signatures in binary data"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"model": "test"}
                pickle.dump(simple_data, f)

                # Add binary content with executable signatures
                f.write(b"some_padding")
                # For Windows PE, we need to include the DOS stub for validation
                f.write(b"MZ")  # Windows PE executable signature
                f.write(b"\x00" * 60)  # Padding to reach DOS stub area
                f.write(b"This program cannot be run in DOS mode")  # DOS stub message
                f.write(b"more_padding")
                f.write(b"\x7fELF")  # Linux ELF executable signature
                f.write(b"end_padding")
                f.flush()

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should find executable signatures
                executable_issues = [
                    issue
                    for issue in result.issues
                    if "executable signature" in issue.message.lower()
                ]
                assert (
                    len(executable_issues) >= 2
                )  # Should find both PE and ELF signatures

                # Check that errors are reported for executable signatures
                error_issues = [
                    issue
                    for issue in executable_issues
                    if issue.severity == IssueSeverity.CRITICAL
                ]
                assert len(error_issues) >= 2

            finally:
                os.unlink(f.name)

    def test_scan_bin_file_clean_binary_content(self):
        """Test scanning .bin file with clean binary content (no issues)"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            try:
                # Write a simple pickle first
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)

                # Add clean binary content (simulating tensor data)
                clean_content = b"\x00" * 1000 + b"\x01" * 500 + b"\xff" * 200
                f.write(clean_content)
                f.flush()

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not find any suspicious patterns in binary content
                binary_issues = [
                    issue
                    for issue in result.issues
                    if "binary data" in issue.message.lower()
                ]
                assert len(binary_issues) == 0

                # Check metadata
                assert "pickle_bytes" in result.metadata
                assert "binary_bytes" in result.metadata
                assert result.metadata["binary_bytes"] > 1000

            finally:
                os.unlink(f.name)

    def test_scan_regular_pickle_file(self):
        """Test that regular .pkl files don't trigger binary content scanning"""
        scanner = PickleScanner()

        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                # Write a simple pickle
                simple_data = {"weights": [1.0, 2.0, 3.0]}
                pickle.dump(simple_data, f)
                f.flush()

                # Scan the file
                result = scanner.scan(f.name)

                # Should complete successfully
                assert result.success

                # Should not have pickle_bytes or binary_bytes metadata (not a .bin file)
                assert "pickle_bytes" not in result.metadata
                assert "binary_bytes" not in result.metadata

            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
