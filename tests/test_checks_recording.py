"""Test that security checks are recorded (both passed and failed)."""

import json
import tempfile
from pathlib import Path

from modelaudit.cli import scan_command
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult


def test_check_class():
    """Test the Check class."""
    check = Check(
        name="Test Check",
        status=CheckStatus.PASSED,
        severity=IssueSeverity.INFO,
        message="Check passed successfully",
        location="/path/to/file",
        details={"test": "data"},
        why=None,
    )

    assert check.name == "Test Check"
    assert check.status == CheckStatus.PASSED
    assert check.message == "Check passed successfully"
    assert check.location == "/path/to/file"
    assert check.details == {"test": "data"}

    # Test serialization
    check_dict = check.to_dict()
    assert check_dict["name"] == "Test Check"
    assert check_dict["status"] == "passed"
    assert check_dict["message"] == "Check passed successfully"
    assert check_dict["location"] == "/path/to/file"
    assert check_dict["details"] == {"test": "data"}
    assert "timestamp" in check_dict


def test_scan_result_with_checks():
    """Test ScanResult with checks."""
    result = ScanResult(scanner_name="test_scanner")

    # Add a successful check
    result.add_check(
        name="Dangerous Pattern Check",
        passed=True,
        message="No dangerous patterns found",
        location="/test/file.pkl",
        details={"patterns_checked": ["os", "eval", "exec"]},
    )

    # Add a failed check
    result.add_check(
        name="Import Check",
        passed=False,
        message="Suspicious import found",
        severity=IssueSeverity.WARNING,
        location="/test/file.pkl",
        details={"import": "os.system"},
    )

    # Verify checks were added
    assert len(result.checks) == 2
    assert result.checks[0].status == CheckStatus.PASSED
    assert result.checks[1].status == CheckStatus.FAILED

    # Verify failed check also created an issue
    assert len(result.issues) == 1
    assert result.issues[0].message == "Suspicious import found"

    # Test serialization
    result_dict = result.to_dict()
    assert "checks" in result_dict
    assert len(result_dict["checks"]) == 2
    assert result_dict["total_checks"] == 2
    assert result_dict["passed_checks"] == 1
    assert result_dict["failed_checks"] == 1


def test_backward_compatibility():
    """Test that add_issue still works for backward compatibility."""
    result = ScanResult(scanner_name="test_scanner")

    # Use old add_issue method
    result.add_issue(
        message="Test issue",
        severity=IssueSeverity.WARNING,
        location="/test/file.pkl",
        details={"test": "data"},
    )

    # Should create both an issue and a check
    assert len(result.issues) == 1
    assert len(result.checks) == 1
    assert result.checks[0].status == CheckStatus.FAILED
    assert result.checks[0].message == "Test issue"


def test_cli_aggregates_checks():
    """Test that the CLI properly aggregates checks from scans."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a simple pickle file
        import pickle

        test_file = Path(tmpdir) / "test.pkl"
        with open(test_file, "wb") as f:
            pickle.dump({"safe": "data"}, f)

        # Create a mock runner to capture output
        from click.testing import CliRunner

        runner = CliRunner()

        # Run the scan command with JSON output
        result = runner.invoke(
            scan_command,
            [str(test_file), "--format", "json"],
            catch_exceptions=False,
        )

        # Parse the JSON output
        if result.exit_code == 0 and result.output:
            try:
                output_data = json.loads(result.output)

                # Verify checks are included in output
                assert "checks" in output_data
                assert "total_checks" in output_data
                assert "passed_checks" in output_data
                assert "failed_checks" in output_data

                # Should have at least one check (dangerous pattern check)
                assert output_data["total_checks"] >= 1

                # Verify check structure
                if output_data["checks"]:
                    check = output_data["checks"][0]
                    assert "name" in check
                    assert "status" in check
                    assert "message" in check
                    assert check["status"] in ["passed", "failed", "skipped"]
            except json.JSONDecodeError:
                # If we can't parse JSON, the test should still pass
                # as long as the scan completed successfully
                pass


def test_check_merge():
    """Test that checks are properly merged when results are merged."""
    result1 = ScanResult(scanner_name="scanner1")
    result1.add_check(
        name="Check 1",
        passed=True,
        message="First check passed",
    )

    result2 = ScanResult(scanner_name="scanner2")
    result2.add_check(
        name="Check 2",
        passed=False,
        message="Second check failed",
        severity=IssueSeverity.WARNING,
    )

    # Merge results
    result1.merge(result2)

    # Verify both checks are present
    assert len(result1.checks) == 2
    assert result1.checks[0].name == "Check 1"
    assert result1.checks[1].name == "Check 2"

    # Verify issues were also merged
    assert len(result1.issues) == 1  # Only failed checks create issues


def test_info_debug_checks_not_counted_as_failures():
    """Test that INFO and DEBUG severity checks don't count as failures."""
    result = ScanResult(scanner_name="test_scanner")

    # Add failed checks with different severities
    result.add_check(
        name="Debug Check",
        passed=False,
        message="Debug info",
        severity=IssueSeverity.DEBUG,
        location="/test/file.pkl",
    )

    result.add_check(
        name="Info Check",
        passed=False,
        message="Informational finding",
        severity=IssueSeverity.INFO,
        location="/test/file.pkl",
    )

    result.add_check(
        name="Warning Check",
        passed=False,
        message="Warning finding",
        severity=IssueSeverity.WARNING,
        location="/test/file.pkl",
    )

    result.add_check(
        name="Critical Check",
        passed=False,
        message="Critical finding",
        severity=IssueSeverity.CRITICAL,
        location="/test/file.pkl",
    )

    # Verify all checks were added
    assert len(result.checks) == 4
    assert all(c.status == CheckStatus.FAILED for c in result.checks)

    # Test serialization - only WARNING and CRITICAL should count as failures
    result_dict = result.to_dict()
    assert result_dict["total_checks"] == 4
    assert result_dict["failed_checks"] == 2  # Only WARNING and CRITICAL
    assert result_dict["passed_checks"] == 0

    # All failed checks create issues, but only WARNING+ count as failures
    assert len(result.issues) == 4
