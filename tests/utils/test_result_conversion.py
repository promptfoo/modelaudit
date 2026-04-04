"""Tests for result conversion utilities."""

from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity, ScanResult
from modelaudit.utils.helpers.result_conversion import scan_result_from_dict, scan_result_to_dict

FIXED_TIMESTAMP = 1_700_000_000.0
FIXED_END_TIME = 1_700_000_100.0


class TestScanResultToDict:
    """Tests for scan_result_to_dict function."""

    def test_basic_conversion(self) -> None:
        """Test basic ScanResult to dict conversion."""
        result = ScanResult(scanner_name="test_scanner")
        result.bytes_scanned = 1000
        result.success = True

        result_dict = scan_result_to_dict(result)

        assert result_dict["scanner"] == "test_scanner"
        assert result_dict["bytes_scanned"] == 1000
        assert result_dict["success"] is True

    def test_with_issues(self) -> None:
        """Test conversion with issues."""
        result = ScanResult(scanner_name="test")
        result.issues.append(
            Issue(
                message="Test issue",
                severity=IssueSeverity.WARNING,
                location="/test/file.pkl",
                details={"key": "value"},
                timestamp=FIXED_TIMESTAMP,
            )
        )

        result_dict = scan_result_to_dict(result)

        assert len(result_dict["issues"]) == 1
        assert result_dict["issues"][0]["message"] == "Test issue"

    def test_with_checks(self) -> None:
        """Test conversion with checks."""
        result = ScanResult(scanner_name="test")
        result.checks.append(
            Check(
                name="test_check",
                status=CheckStatus.PASSED,
                message="Check passed",
                timestamp=FIXED_TIMESTAMP,
            )
        )

        result_dict = scan_result_to_dict(result)

        assert len(result_dict["checks"]) == 1
        assert result_dict["checks"][0]["name"] == "test_check"

    def test_with_metadata(self) -> None:
        """Test conversion with metadata."""
        result = ScanResult(scanner_name="test")
        result.metadata = {"format": "pickle", "version": "4"}

        result_dict = scan_result_to_dict(result)

        assert result_dict["metadata"]["format"] == "pickle"


class TestScanResultFromDict:
    """Tests for scan_result_from_dict function."""

    def test_basic_conversion(self) -> None:
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

    def test_with_issues(self) -> None:
        """Test conversion with issues."""
        result_dict = {
            "scanner": "test",
            "issues": [
                {
                    "message": "Test issue",
                    "severity": "warning",
                    "location": "/test/file.pkl",
                    "details": {"key": "value"},
                    "timestamp": FIXED_TIMESTAMP,
                }
            ],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert len(result.issues) == 1
        assert result.issues[0].message == "Test issue"
        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_with_checks(self) -> None:
        """Test conversion with checks."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [
                {
                    "name": "test_check",
                    "status": "passed",
                    "message": "Check passed",
                    "timestamp": FIXED_TIMESTAMP,
                }
            ],
        }

        result = scan_result_from_dict(result_dict)

        assert len(result.checks) == 1
        assert result.checks[0].name == "test_check"
        assert result.checks[0].status == CheckStatus.PASSED

    def test_severity_normalization_warn(self) -> None:
        """Test 'warn' is normalized to 'warning'."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "warn", "timestamp": FIXED_TIMESTAMP}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_severity_normalization_error(self) -> None:
        """Test 'error' is normalized to 'critical'."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "error", "timestamp": FIXED_TIMESTAMP}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.CRITICAL

    def test_severity_normalization_invalid(self) -> None:
        """Test invalid severity defaults to WARNING."""
        result_dict = {
            "scanner": "test",
            "issues": [{"message": "Test", "severity": "invalid_value", "timestamp": FIXED_TIMESTAMP}],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.issues[0].severity == IssueSeverity.WARNING

    def test_check_status_normalization_ok(self) -> None:
        """Test 'ok' is normalized to 'passed'."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "ok", "message": "", "timestamp": FIXED_TIMESTAMP}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.PASSED

    def test_check_status_normalization_fail(self) -> None:
        """Test 'fail' is normalized to 'failed'."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "fail", "message": "", "timestamp": FIXED_TIMESTAMP}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.FAILED

    def test_check_status_normalization_invalid(self) -> None:
        """Test invalid status defaults to PASSED."""
        result_dict = {
            "scanner": "test",
            "issues": [],
            "checks": [{"name": "test", "status": "invalid", "message": "", "timestamp": FIXED_TIMESTAMP}],
        }

        result = scan_result_from_dict(result_dict)

        assert result.checks[0].status == CheckStatus.PASSED

    def test_end_time_from_duration(self) -> None:
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

    def test_end_time_explicit(self) -> None:
        """Test explicit end_time is preserved."""
        result_dict = {
            "scanner": "test",
            "end_time": FIXED_END_TIME,
            "issues": [],
            "checks": [],
        }

        result = scan_result_from_dict(result_dict)

        assert result.end_time == FIXED_END_TIME

    def test_metadata_restored(self) -> None:
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

    def test_missing_optional_fields(self) -> None:
        """Test handling of missing optional fields."""
        result_dict = {"scanner": "test", "issues": [], "checks": []}

        result = scan_result_from_dict(result_dict)

        assert result.bytes_scanned == 0
        assert result.success is True


class TestRoundTrip:
    """Tests for round-trip conversion."""

    def test_roundtrip_basic(self) -> None:
        """Test round-trip conversion."""
        original = ScanResult(scanner_name="test")
        original.bytes_scanned = 1000
        original.success = True

        # Convert to dict and back
        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert restored.scanner_name == original.scanner_name
        assert restored.bytes_scanned == original.bytes_scanned

    def test_roundtrip_with_issues(self) -> None:
        """Test round-trip with issues."""
        original = ScanResult(scanner_name="test")
        original.issues.append(
            Issue(
                message="Test issue",
                severity=IssueSeverity.CRITICAL,
                location="/test/file.pkl",
                timestamp=FIXED_TIMESTAMP,
            )
        )

        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert len(restored.issues) == 1
        assert restored.issues[0].message == original.issues[0].message

    def test_roundtrip_with_checks(self) -> None:
        """Test round-trip with checks."""
        original = ScanResult(scanner_name="test")
        original.checks.append(
            Check(
                name="security_check",
                status=CheckStatus.FAILED,
                message="Security issue found",
                timestamp=FIXED_TIMESTAMP,
            )
        )

        result_dict = scan_result_to_dict(original)
        restored = scan_result_from_dict(result_dict)

        assert len(restored.checks) == 1
        assert restored.checks[0].name == original.checks[0].name

    def test_roundtrip_preserves_rule_codes(self) -> None:
        """Rule codes should survive cache serialization and restoration."""
        original = ScanResult(scanner_name="pickle")
        original.issues.append(
            Issue(
                message="Found REDUCE opcode invoking dangerous global: os.system",
                severity=IssueSeverity.CRITICAL,
                location="/tmp/model.pkl (pos 42)",
                timestamp=FIXED_TIMESTAMP,
                rule_code="S201",
            )
        )
        original.checks.append(
            Check(
                name="REDUCE Opcode Safety Check",
                status=CheckStatus.FAILED,
                message="Found REDUCE opcode invoking dangerous global: os.system",
                severity=IssueSeverity.CRITICAL,
                location="/tmp/model.pkl (pos 42)",
                timestamp=FIXED_TIMESTAMP,
                rule_code="S201",
            )
        )

        restored = scan_result_from_dict(scan_result_to_dict(original))

        assert restored.issues[0].rule_code == "S201"
        assert restored.checks[0].rule_code == "S201"
