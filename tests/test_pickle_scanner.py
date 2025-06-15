import os
import pickle
import sys
import unittest
from pathlib import Path

# Add the parent directory to sys.path to allow importing modelaudit
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import only what we need for the pickle scanner test
from modelaudit.scanners.pickle_scanner import PickleScanner


class EvilClass:
    def __reduce__(self):
        # This is a harmless example for testing
        # In a real attack, this might do something malicious
        return (os.system, ("echo 'This could be malicious'",))


class TestPickleScanner(unittest.TestCase):
    def setUp(self):
        # Path to evil.pickle sample
        self.evil_pickle_path = os.path.join(os.path.dirname(__file__), "evil.pickle")

        # Create the evil pickle if it doesn't exist
        if not os.path.exists(self.evil_pickle_path):
            evil_obj = EvilClass()
            with open(self.evil_pickle_path, "wb") as f:
                pickle.dump(evil_obj, f)

    def test_scan_evil_pickle(self):
        """Test that the scanner can detect the malicious pickle created by evil_pickle.py"""
        scanner = PickleScanner()
        result = scanner.scan(self.evil_pickle_path)

        # Check that the scan completed successfully
        self.assertTrue(result.success)

        # Check that issues were found
        self.assertTrue(result.has_errors)

        # Print the found issues for debugging
        print("\nIssues found in evil.pickle:")
        for issue in result.issues:
            print(f"- {issue}")

        # Check for specific pattern detections
        has_reduce_detection = False
        has_os_system_detection = False

        for issue in result.issues:
            if "REDUCE" in issue.message:
                has_reduce_detection = True
            if "os.system" in issue.message or (
                "os" in issue.message and "system" in issue.message
            ):
                has_os_system_detection = True

        self.assertTrue(has_reduce_detection, "Failed to detect REDUCE opcode")
        self.assertTrue(has_os_system_detection, "Failed to detect os.system reference")


if __name__ == "__main__":
    unittest.main()
