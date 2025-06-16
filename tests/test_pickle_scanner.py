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
        assert (
            has_os_system_detection
        ), "Failed to detect os.system/posix.system reference"

    def test_scan_nonexistent_file(self):
        """Scanner returns failure and error issue for missing file"""
        scanner = PickleScanner()
        result = scanner.scan("nonexistent_file.pkl")

        assert result.success is False
        assert any(issue.severity == IssueSeverity.ERROR for issue in result.issues)


if __name__ == "__main__":
    unittest.main()
