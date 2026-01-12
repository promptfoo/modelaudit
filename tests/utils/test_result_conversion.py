"""Tests for result conversion utilities."""

import time

from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity, ScanResult
from modelaudit.utils.result_conversion import scan_result_from_dict, scan_result_to_dict


class TestScanResultToDict:
    """Tests for scan_result_to_dict function."""

    def test_basic_conversion(self):
        """Test basic ScanResult to dict conversion."""
        result = ScanResult(scanner_name="test_scanner")
        result.bytes_scanned = 1000
        result.success = True

        result_dict = scan_result_to_dict(result)

        assert result_dict["scanner"] == "test_scanner"
        assert result_dict["bytes_scanned"] == 1000
        assert result_dict["success"] is True

    def test_with_issues(self):
        """Test conversion with issues."""
        result = ScanResult(scanner_name="test")
        result.issues.append(
            Issue(
                message="Test issue",
                severity=IssueSeverity.WARNING,
                location="/test/file.pkl",
                details={"key": "value"},
                timestamp=time.time(),
            )
        )

        result_dict = scan_result_to_dict(result)

        assert len(result_dict["issues"]) == 1
        assert result_dict["issues"][0]["message"] == "Test issue"

    def test_with_checks(self):
        """Test conversion with checks."""
        result = ScanResult(scanner_name="test")
        result.checks.append(
            Check(
                name="test_check",
                status=CheckStatus.PASSED,
                message="Check passed",
                timestamp=time.time(),
            )
        )

        result_dict = scan_result_to_dict(result)

        assert len(result_dict["checks"]) == 1
        assert result_dict["checks"][0]["name"] == "test_check"

    def test_with_metadata(self):
        """Test conversion with metadata."""
        result = ScanResult(scanner_name="test")
        result.metadata = {"format": "pickle", "version": "4"}

        result_dict = scan_result_to_dict(result)

        assert result_dict["metadata"]["format"] == "pickle"


class TestScanResultFromDict:
    """Tests for scan_result_from_dict function."""

    def test_basic_conversion(self):
        """Test basic dict to ScanResult conversion."""
        result_dict = {
            "scanner": "test_scanner",
            "bytes_scanned": 1000,
            "success": True,
            "duration": 1.5,
            "metadata": {},
            "issues": [],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.scanner_name == "test_scanner"
        assert result.bytes_scanned == 1000
        assert result.success is True

    def test_with_issues(self):
        """Test conversion with issues."""
        result_dict = {
            "scanner": "test",
            "issues": [
                {
                    "message": "Test issue",
                    "severity": "warning",
                    "location": "/test/file.pkl",
                    "details": {"key": "value"},
                    "timestamp": time.time(),
                }
            ],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert len(result.issues) == 1
        assert result.issues[0].message == "Test issue"
        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_with_checks(self):
        """Test conversion with checks."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [
                {
                    "name": "test_check",
                    "status": "passed",
                    "message": "Check passed",
                    "timestamp": time.time(),
                }
            ],
        }

        result = scan_result_from_dict(result_dict)

        assert len(result.checks) == 1
        assert result.checks[0].name == "test_check"
        assert result.checks[0].status == CheckStatus.PASSED

    def test_severity_normalization_warn(self):
        """Test 'warn' is normalized to 'warning'."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "warn", "timestamp": time.time()}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_severity_normalization_error(self):
        """Test 'error' is normalized to 'critical'."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "error", "timestamp": time.time()}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.CRITICAL

    def test_severity_normalization_invalid(self):
        """Test invalid severity defaults to WARNING."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "invalid_value", "timestamp": time.time()}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_check_status_normalization_ok(self):
        """Test 'ok' is normalized to 'passed'."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "ok", "message": "", "timestamp": time.time()}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.PASSED

    def test_check_status_normalization_fail(self):
        """Test 'fail' is normalized to 'failed'."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "fail", "message": "", "timestamp": time.time()}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.FAILED

    def test_check_status_normalization_invalid(self):
        """Test invalid status defaults to PASSED."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "invalid", "message": "", "timestamp": time.time()}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.PASSED

    def test_end_time_from_duration(self):
        """Test end_time is calculated from duration."""
        result_dict = {
            "scanner": "test",
            "duration": 2.0,
            "issues": [],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        # end_time should be set based on start_time + duration
        assert result.end_time is not None

    def test_end_time_explicit(self):
        """Test explicit end_time is preserved."""
        explicit_end = time.time() + 100
        result_dict = {
            "scanner": "test",
            "end_time": explicit_end,
            "issues": [],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.end_time == explicit_end

    def test_metadata_restored(self):
        """Test metadata is restored."""
        result_dict = {
            "scanner": "test",
            "metadata": {"format": "pickle", "version": "4"},
            "issues": [],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.metadata["format"] == "pickle"
        assert result.metadata["version"] == "4"

    def test_missing_optional_fields(self):
        """Test handling of missing optional fields."""
        result_dict = {"scanner": "test", "issues": [], "checks": []}

        result = scan_result_from_dict(result_dict)

        assert result.bytes_scanned == 0
        assert result.success is True


class TestRoundTrip:
    """Tests for round-trip conversion."""

    def test_roundtrip_basic(self):
        """Test round-trip conversion."""
        original = ScanResult(scanner_name="test")
        original.bytes_scanned = 1000
        original.success = True

        # Convert to dict and back
        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert restored.scanner_name == original.scanner_name
        assert restored.bytes_scanned == original.bytes_scanned

    def test_roundtrip_with_issues(self):
        """Test round-trip with issues."""
        original = ScanResult(scanner_name="test")
        original.issues.append(
            Issue(
                message="Test issue",
                severity=IssueSeverity.CRITICAL,
                location="/test/file.pkl",
                timestamp=time.time(),
            )
        )

        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert len(restored.issues) == 1
        assert restored.issues[0].message == original.issues[0].message

    def test_roundtrip_with_checks(self):
        """Test round-trip with checks."""
        original = ScanResult(scanner_name="test")
        original.checks.append(
            Check(
                name="security_check",
                status=CheckStatus.FAILED,
                message="Security issue found",
                timestamp=time.time(),
            )
        )

        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert len(restored.checks) == 1
        assert restored.checks[0].name == original.checks[0].name
