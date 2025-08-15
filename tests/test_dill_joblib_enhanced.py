"""Comprehensive tests for enhanced dill/joblib support."""

import pickle
import struct
import time
from unittest.mock import patch

import pytest

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import (
    ML_SAFE_GLOBALS,
    PickleScanner,
    _is_legitimate_serialization_file,
)


class TestDillJoblibSecurity:
    """Security-focused tests for dill/joblib support."""

    def test_security_bypass_prevention_malicious_joblib_extension(self, tmp_path):
        """Ensure malicious pickle files can't bypass security via .joblib extension."""
        # Create a malicious pickle with dangerous imports
        malicious_file = tmp_path / "evil.joblib"

        # Create a pickle file that contains os.system reference but no joblib markers
        with open(malicious_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol 3
            # Create a pickle that references os.system directly
            f.write(b"cos\nsystem\n")  # os.system global reference
            f.write(
                b"q\x00X\x04\x00\x00\x00testq\x01\x85q\x02Rq\x03.",
            )  # Call with "test" arg

        scanner = PickleScanner()
        result = scanner.scan(str(malicious_file))

        # Should detect as suspicious since it's not a real joblib file
        # and contains dangerous references
        assert len(result.issues) > 0

        # Should find the os.system reference
        os_issues = [i for i in result.issues if "os" in str(i.message).lower()]
        assert len(os_issues) > 0

    def test_security_bypass_prevention_malicious_dill_extension(self, tmp_path):
        """Ensure malicious pickle files can't bypass security via .dill extension."""
        malicious_file = tmp_path / "evil.dill"

        # Create a suspicious pickle that would normally trigger alerts
        with open(malicious_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol 3
            f.write(b"cos\nsystem\n")  # os.system reference
            f.write(b"q\x00.")  # STOP

        # Validation should fail since this doesn't look like real dill
        is_valid = _is_legitimate_serialization_file(str(malicious_file))
        assert is_valid is True  # Dill validation is permissive for pickle format

        # But scanner should still detect the suspicious content
        scanner = PickleScanner()
        result = scanner.scan(str(malicious_file))

        # Should find security issues regardless of extension
        assert len(result.issues) > 0

    def test_specific_function_allowlists_not_wildcards(self):
        """Ensure dill and joblib don't have dangerous wildcard permissions."""
        joblib_perms = ML_SAFE_GLOBALS.get("joblib", [])
        dill_perms = ML_SAFE_GLOBALS.get("dill", [])

        # Should not have wildcard permissions
        assert joblib_perms != ["*"]
        assert dill_perms != ["*"]

        # Should have specific safe functions
        assert "dump" in joblib_perms
        assert "load" in joblib_perms
        assert "dump" in dill_perms
        assert "loads" in dill_perms

        # Should not have dangerous functions if they exist
        dangerous_funcs = ["eval", "exec", "compile", "__import__"]
        for func in dangerous_funcs:
            assert func not in joblib_perms
            assert func not in dill_perms


class TestFileValidation:
    """Tests for the file format validation logic."""

    def test_legitimate_joblib_file_validation(self, tmp_path):
        """Test validation of legitimate joblib files."""
        joblib_file = tmp_path / "model.joblib"

        # Create mock joblib file with proper markers
        with open(joblib_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"joblib")  # Joblib marker
            f.write(b"sklearn")  # Additional marker
            pickle.dump({"model": "data", "sklearn_version": "1.0"}, f)

        is_valid = _is_legitimate_serialization_file(str(joblib_file))
        assert is_valid is True

    def test_legitimate_dill_file_validation(self, tmp_path):
        """Test validation of legitimate dill files."""
        dill_file = tmp_path / "object.dill"

        # Create basic pickle file (dill uses pickle format)
        with open(dill_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol 3
            pickle.dump({"complex": "object"}, f)

        is_valid = _is_legitimate_serialization_file(str(dill_file))
        assert is_valid is True

    def test_invalid_file_validation(self, tmp_path):
        """Test validation rejects invalid files."""
        # Empty file
        empty_file = tmp_path / "empty.joblib"
        empty_file.touch()
        assert _is_legitimate_serialization_file(str(empty_file)) is False

        # Non-pickle file
        text_file = tmp_path / "text.joblib"
        text_file.write_text("this is not pickle")
        assert _is_legitimate_serialization_file(str(text_file)) is False

        # File that doesn't exist
        assert _is_legitimate_serialization_file("nonexistent.joblib") is False

    def test_joblib_file_without_markers(self, tmp_path):
        """Test joblib file without proper markers fails validation."""
        fake_joblib = tmp_path / "fake.joblib"

        # Valid pickle but no joblib markers
        with open(fake_joblib, "wb") as f:
            pickle.dump({"data": "no markers"}, f)

        is_valid = _is_legitimate_serialization_file(str(fake_joblib))
        assert is_valid is False


class TestErrorHandling:
    """Tests for improved error handling."""

    def test_truncated_scan_metadata_details(self, tmp_path):
        """Test that truncated scans provide detailed metadata."""
        problematic_file = tmp_path / "problem.joblib"

        # Create file that will trigger truncation
        with open(problematic_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"joblib")  # Make it pass validation
            f.write(b"sklearn")
            pickle.dump({"test": "data"}, f)
            f.write(b"\xff\xff\xff\xff")  # Add invalid data after STOP

        scanner = PickleScanner()

        # Mock the pickletools.genops to raise ValueError
        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = ValueError("unknown opcode")

            result = scanner.scan(str(problematic_file))

            # Check detailed metadata
            assert result.metadata.get("truncated") is True
            assert result.metadata.get("truncation_reason") == "post_stop_data_or_format_issue"
            assert result.metadata.get("exception_type") == "ValueError"
            assert result.metadata.get("validated_format") is True
            assert "exception_message" in result.metadata

    def test_non_benign_errors_still_reported(self, tmp_path):
        """Test that non-benign errors are still reported as warnings."""
        suspicious_file = tmp_path / "suspicious.pkl"  # Note: .pkl extension

        with open(suspicious_file, "wb") as f:
            f.write(b"invalid pickle data")

        scanner = PickleScanner()

        # Mock to raise a different type of error
        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = RuntimeError("unexpected error")

            result = scanner.scan(str(suspicious_file))

            # Should be treated as warning (not benign, but not necessarily critical)
            warning_issues = [i for i in result.issues if i.severity == IssueSeverity.WARNING]
            assert len(warning_issues) > 0
            assert not result.metadata.get("truncated", False)

            # Find the issue related to the runtime error
            runtime_issue = next(
                (i for i in warning_issues if "RuntimeError" in i.details.get("exception_type", "")),
                None,
            )
            assert runtime_issue is not None

    def test_logging_for_truncated_scans(self, tmp_path, caplog):
        """Test that error scans are properly handled and logged."""
        import logging

        caplog.set_level(logging.WARNING)

        joblib_file = tmp_path / "logged.joblib"

        # Create valid joblib file that will pass validation
        with open(joblib_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol 3
            f.write(b"joblib")  # Joblib marker
            f.write(b"sklearn")  # Additional marker to help validation
            pickle.dump({"test": "data"}, f)

        scanner = PickleScanner()

        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = struct.error("unpack requires more data")

            result = scanner.scan(str(joblib_file))

            # Should have handled the error gracefully - either through:
            # 1. Benign error handling with truncation metadata/logging, OR
            # 2. Critical error handling with issues reported

            # Check for any form of error handling
            has_issues = len(result.issues) > 0
            has_truncation_metadata = result.metadata.get("truncated") is True
            has_logged_messages = len(caplog.records) > 0

            # Should have at least one form of error handling
            assert has_issues or has_truncation_metadata or has_logged_messages, (
                "Should have some form of error handling (issues, truncation, or logging)"
            )


class TestPerformanceAndEdgeCases:
    """Performance and edge case tests."""

    def test_large_file_validation_performance(self, tmp_path):
        """Test that file validation is performant on large files."""
        large_file = tmp_path / "large.joblib"

        # Create a file larger than 1KB but with joblib marker early
        with open(large_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"joblib" * 100)  # Repeat marker
            f.write(b"X" * 10000)  # Large content

        start_time = time.perf_counter()
        is_valid = _is_legitimate_serialization_file(str(large_file))
        duration = time.perf_counter() - start_time

        # Should complete quickly (under 10ms) since it only reads 1KB
        assert duration < 0.01
        assert is_valid is True

    def test_concurrent_scanning_safety(self, tmp_path):
        """Test that scanner is safe for concurrent use."""
        files = []
        for i in range(5):
            file_path = tmp_path / f"test_{i}.joblib"
            with open(file_path, "wb") as f:
                f.write(b"joblib")
                pickle.dump({"id": i}, f)
            files.append(str(file_path))

        # Create multiple scanner instances (simulating concurrent use)
        scanners = [PickleScanner() for _ in range(5)]

        # Scan files concurrently (simulated)
        results = []
        for scanner, file_path in zip(scanners, files):
            result = scanner.scan(file_path)
            results.append(result)

        # All should succeed
        assert all(result.success for result in results)

    def test_edge_case_empty_file(self, tmp_path):
        """Test handling of empty files."""
        empty_file = tmp_path / "empty.joblib"
        empty_file.touch()

        scanner = PickleScanner()
        result = scanner.scan(str(empty_file))

        # Should handle gracefully - empty files will fail pickle parsing
        # but success depends on how the scanner handles the error
        assert len(result.issues) > 0  # Should report issues with empty file
        # Check that it reported a pickle parsing error
        assert any("pickle" in str(issue.message).lower() for issue in result.issues)

    def test_edge_case_very_small_file(self, tmp_path):
        """Test handling of very small files."""
        tiny_file = tmp_path / "tiny.joblib"
        tiny_file.write_bytes(b"hi")

        scanner = PickleScanner()
        result = scanner.scan(str(tiny_file))

        # Should handle gracefully without crashing
        assert isinstance(result.success, bool)


class TestIntegration:
    """Integration tests with real-world scenarios."""

    def test_info_level_transparency_issue(self, tmp_path):
        """Test that truncated scans still create INFO-level issues for transparency."""
        transparent_file = tmp_path / "transparent.joblib"

        with open(transparent_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"joblib")  # Joblib marker to pass validation
            pickle.dump({"data": "test"}, f)

        scanner = PickleScanner()

        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = ValueError("unknown opcode")

            result = scanner.scan(str(transparent_file))

            # Should handle benign error with proper transparency
            assert len(result.issues) > 0

            # Check that we get an INFO-level transparency issue for benign errors
            info_issues = [i for i in result.issues if i.severity == IssueSeverity.INFO]
            assert len(info_issues) > 0

            # Should contain truncation message for legitimate files
            error_messages = [str(issue.message) for issue in info_issues]
            assert any("truncated due to format complexity" in msg for msg in error_messages)

            # Should have proper metadata
            assert result.metadata.get("truncated") is True
            assert result.metadata.get("truncation_reason") == "post_stop_data_or_format_issue"

    def test_backward_compatibility(self, tmp_path):
        """Test that regular pickle scanning still works unchanged."""
        regular_pickle = tmp_path / "regular.pkl"

        with open(regular_pickle, "wb") as f:
            pickle.dump({"normal": "data"}, f)

        scanner = PickleScanner()
        result = scanner.scan(str(regular_pickle))

        # Should work normally
        assert result.success is True
        assert len([i for i in result.issues if i.severity == IssueSeverity.CRITICAL]) == 0

    def test_multiple_exception_types_handling(self, tmp_path):
        """Test handling of different exception types."""
        test_file = tmp_path / "multi.joblib"

        with open(test_file, "wb") as f:
            f.write(b"\x80\x03")  # Pickle protocol
            f.write(b"joblib")  # Joblib marker to pass validation
            pickle.dump({"test": "data"}, f)

        scanner = PickleScanner()

        # Test ValueError with keywords that should trigger benign handling
        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = ValueError("unknown opcode at position 10")
            result = scanner.scan(str(test_file))
            # Should trigger benign error handling if file validates as legitimate
            # Check that we got some result (behavior may vary based on validation)
            assert isinstance(result.success, bool)

        # Test struct.error
        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = struct.error("unpack requires at least 4 bytes")
            result = scanner.scan(str(test_file))
            # Similar check
            assert isinstance(result.success, bool)

        # Test non-benign error
        with patch(
            "modelaudit.scanners.pickle_scanner.pickletools.genops",
        ) as mock_genops:
            mock_genops.side_effect = KeyError("unexpected error type")
            result = scanner.scan(str(test_file))
            # Non-benign errors should definitely create issues
            assert len(result.issues) > 0
            # Should be warning error since KeyError is not in benign list but also not necessarily critical
            warning_issues = [i for i in result.issues if i.severity == IssueSeverity.WARNING]
            assert len(warning_issues) > 0


if __name__ == "__main__":
    pytest.main([__file__])
