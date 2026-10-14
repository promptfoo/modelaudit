"""
Test timeout configuration and progressive scanning functionality.

This tests the ability to configure timeouts, handle timeout errors gracefully,
and provide partial results when scans exceed the configured timeout.
"""

import shutil
import time
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

from modelaudit.core import scan_file, scan_model_directory_or_file
from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult


class SlowTestScanner(BaseScanner):
    """A test scanner that simulates slow scanning"""

    name = "slow_test"
    supported_extensions: ClassVar[list[str]] = [".slow"]

    def scan(self, path: str) -> ScanResult:
        """Scan method that simulates slow processing"""
        self._start_scan_timer()
        result = self._create_result()

        # Simulate slow scanning
        file_size = self.get_file_size(path)
        bytes_per_iteration = 1024
        bytes_scanned = 0

        while bytes_scanned < file_size:
            # Check for timeout
            if self._check_timeout(allow_partial=True):
                # Add partial results
                self._add_timeout_warning(result, bytes_scanned, file_size)
                break

            # Simulate slow processing
            time.sleep(0.1)  # Sleep 100ms per iteration
            bytes_scanned += bytes_per_iteration

        result.bytes_scanned = bytes_scanned
        result.finish(success=True)
        return result


class TestTimeoutConfiguration:
    """Test timeout configuration functionality"""

    def test_timeout_in_cli(self):
        """Test that timeout option exists in CLI"""
        from click.testing import CliRunner

        from modelaudit.cli import cli

        runner = CliRunner()
        # Check the scan command help since timeout is a scan option
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--timeout" in result.output or "-t" in result.output

    def test_timeout_passed_to_scanner(self):
        """Test that timeout is passed from config to scanner"""
        scanner = SlowTestScanner(config={"timeout": 10})
        assert scanner.timeout == 10

    def test_default_timeout(self):
        """Test default timeout value"""
        scanner = SlowTestScanner()
        assert scanner.timeout == 3600  # Default 1 hour for large models

    def test_timeout_error_handling(self, tmp_path: Path) -> None:
        """Test that TimeoutError is caught and handled gracefully"""
        model_path = tmp_path / "model.pkl"
        model_path.touch(mode=0o600)
        model_path.write_bytes(b"\x80\x05\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x0ctest content\x94.")

        # Mock the scanner to raise TimeoutError
        with patch("modelaudit.scanners.pickle_scanner.PickleScanner.scan") as mock_scan:
            mock_scan.side_effect = TimeoutError("Test timeout")

            result = scan_file(str(model_path), config={"timeout": 1})

            # Should return a result with timeout warning
            assert not result.success
            assert any("timeout" in issue.message.lower() for issue in result.issues)
        # Delete before fixture teardown to catch leaked file handles.
        model_path.unlink()

    @pytest.mark.slow
    def test_partial_results_on_timeout(self, tmp_path: Path) -> None:
        """Test that partial results are returned when timeout occurs"""
        # Create a large test file with 10KB of data
        model_path = tmp_path / "model.slow"
        model_path.touch(mode=0o600)
        model_path.write_bytes(b"x" * 10240)

        scanner = SlowTestScanner(config={"timeout": 0.5})  # 500ms timeout
        result = scanner.scan(str(model_path))

        # Should have partial results
        assert result.bytes_scanned > 0
        assert result.bytes_scanned < 10240  # Should not have scanned everything

        # Should have timeout warning
        timeout_warnings = [i for i in result.issues if "timeout" in i.message.lower()]
        assert len(timeout_warnings) > 0

        # Check the warning has proper details
        warning = timeout_warnings[0]
        assert warning.details["bytes_scanned"] > 0
        assert warning.details["total_bytes"] == 10240
        assert 0 < warning.details["percentage_complete"] < 100
        model_path.unlink()

    def test_timeout_in_directory_scan(self, tmp_path: Path) -> None:
        """Test timeout handling during directory scanning"""
        # Create multiple files
        for i in range(3):
            (tmp_path / f"file{i}.pkl").write_bytes(
                b"\x80\x05\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x0ctest content\x94."
            )

        # Scan with short timeout (1 second)
        results = scan_model_directory_or_file(str(tmp_path), timeout=1)

        # Should complete and return results
        assert hasattr(results, "files_scanned")
        assert results.files_scanned >= 0
        shutil.rmtree(tmp_path)

    def test_check_timeout_methods(self):
        """Test the timeout checking helper methods"""
        scanner = SlowTestScanner(config={"timeout": 1})

        # Start timer
        scanner._start_scan_timer()

        # Should not timeout immediately
        assert not scanner._check_timeout(allow_partial=True)

        # Should have remaining time
        remaining = scanner._get_remaining_time()
        assert 0 < remaining <= 1

        # Simulate timeout
        scanner.scan_start_time = time.time() - 2  # 2 seconds ago

        # Should return True when allow_partial=True
        assert scanner._check_timeout(allow_partial=True)

        # Should raise when allow_partial=False
        with pytest.raises(TimeoutError):
            scanner._check_timeout(allow_partial=False)

    def test_add_timeout_warning(self):
        """Test adding timeout warning to results"""
        scanner = SlowTestScanner()
        result = ScanResult(scanner_name="test")
        scanner.current_file_path = "/test/file.bin"

        scanner._add_timeout_warning(result, 5000, 10000)

        # Check warning was added
        timeout_issues = [i for i in result.issues if "incomplete" in i.message.lower()]
        assert len(timeout_issues) == 1

        issue = timeout_issues[0]
        assert issue.severity == IssueSeverity.WARNING
        assert issue.details["bytes_scanned"] == 5000
        assert issue.details["total_bytes"] == 10000
        assert issue.details["percentage_complete"] == 50.0

    def test_timeout_with_zero_value(self):
        """Test that zero or negative timeout values are rejected"""
        from modelaudit.core import validate_scan_config

        with pytest.raises(ValueError, match="Input should be greater than 0"):
            validate_scan_config({"timeout": 0})

        with pytest.raises(ValueError, match="Input should be greater than 0"):
            validate_scan_config({"timeout": -1})

        with pytest.raises(ValueError, match="unable to parse string as an integer"):
            validate_scan_config({"timeout": "invalid"})


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
