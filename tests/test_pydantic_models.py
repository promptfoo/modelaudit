"""Tests for Pydantic models that match current JSON format."""

import json
import time

import pytest

# Ensure models are rebuilt for forward references
from modelaudit.models import (
    ModelAuditResultModel,
    create_audit_result_model,
    rebuild_models,
)
from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity

rebuild_models()


class TestPydanticModels:
    """Test Pydantic model functionality for current JSON format."""

    def test_issue_model_creation(self):
        """Test Issue creation and serialization."""
        timestamp = time.time()
        issue = Issue(
            message="Test issue",
            severity=IssueSeverity.WARNING,
            location="/path/to/file.pkl",
            details={"key": "value"},
            timestamp=timestamp,
            why="This is why it's a problem",
        )

        assert issue.message == "Test issue"
        assert issue.severity == IssueSeverity.WARNING
        assert issue.location == "/path/to/file.pkl"
        assert issue.details == {"key": "value"}
        assert issue.timestamp == timestamp
        assert issue.why == "This is why it's a problem"

        # Test serialization
        issue_dict = issue.model_dump()
        assert issue_dict["severity"] == "warning"  # Enum serializes to its value

    def test_check_model_creation(self):
        """Test Check creation and serialization."""
        timestamp = time.time()
        check = Check(
            name="Test Check",
            status=CheckStatus.FAILED,
            message="Check failed",
            severity=IssueSeverity.CRITICAL,
            location="/path/to/file.pkl",
            details={"error": "details"},
            timestamp=timestamp,
            why="Explanation of failure",
        )

        assert check.name == "Test Check"
        assert check.status == CheckStatus.FAILED
        assert check.message == "Check failed"
        assert check.severity == IssueSeverity.CRITICAL
        assert check.location == "/path/to/file.pkl"
        assert check.details == {"error": "details"}
        assert check.timestamp == timestamp
        assert check.why == "Explanation of failure"

    def test_model_audit_result_creation(self):
        """Test ModelAuditResultModel creation."""
        result = ModelAuditResultModel(
            bytes_scanned=1000,
            issues=[],
            checks=[],
            files_scanned=1,
            assets=[],
            has_errors=False,
            scanner_names=["test_scanner"],
            file_metadata={},
            start_time=time.time(),
            duration=1.5,
            total_checks=5,
            passed_checks=5,
            failed_checks=0,
        )

        assert result.bytes_scanned == 1000
        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.scanner_names == ["test_scanner"]
        assert result.duration == 1.5
        assert result.total_checks == 5

    def test_create_audit_result_model(self):
        """Test creating ModelAuditResultModel from aggregated results."""
        aggregated_results = {
            "bytes_scanned": 2000,
            "issues": [
                {
                    "message": "Critical issue",
                    "severity": "critical",
                    "location": "/path/to/file1.pkl",
                    "details": {},
                    "timestamp": time.time(),
                }
            ],
            "checks": [
                {
                    "name": "Test Check 1",
                    "status": "failed",
                    "message": "Check failed",
                    "severity": "critical",
                    "location": "/path/to/file1.pkl",
                    "details": {},
                    "timestamp": time.time(),
                }
            ],
            "files_scanned": 2,
            "assets": [{"path": "test.pkl", "type": "pickle", "size": 100}],
            "has_errors": True,
            "scanner_names": ["pickle"],
            "file_metadata": {},
            "start_time": time.time(),
            "duration": 1.0,
            "total_checks": 1,
            "passed_checks": 0,
            "failed_checks": 1,
        }

        model = create_audit_result_model(aggregated_results)

        assert isinstance(model, ModelAuditResultModel)
        assert model.bytes_scanned == 2000
        assert len(model.issues) == 1
        assert len(model.checks) == 1
        assert model.files_scanned == 2
        assert len(model.assets) == 1
        assert model.has_errors is True
        assert model.scanner_names == ["pickle"]

    def test_json_serialization_matches_format(self):
        """Test that model JSON serialization matches expected format."""
        # Create a realistic model
        model = ModelAuditResultModel(
            bytes_scanned=100,
            issues=[Issue(message="Test issue", severity=IssueSeverity.WARNING, timestamp=time.time())],
            checks=[Check(name="Test Check", status=CheckStatus.PASSED, message="Check passed", timestamp=time.time())],
            files_scanned=1,
            assets=[{"path": "test.pkl", "type": "pickle"}],
            has_errors=False,
            scanner_names=["pickle"],
            file_metadata={},
            start_time=time.time(),
            duration=1.0,
            total_checks=1,
            passed_checks=1,
            failed_checks=0,
        )

        # Serialize to JSON and verify structure
        json_str = model.model_dump_json(indent=2, exclude_none=True)
        parsed = json.loads(json_str)

        # Check that all expected top-level keys are present
        expected_keys = {
            "bytes_scanned",
            "issues",
            "checks",
            "files_scanned",
            "assets",
            "has_errors",
            "scanner_names",
            "file_metadata",
            "start_time",
            "duration",
            "total_checks",
            "passed_checks",
            "failed_checks",
        }
        assert set(parsed.keys()) >= expected_keys

        # Check types and structure
        assert isinstance(parsed["bytes_scanned"], int)
        assert isinstance(parsed["issues"], list)
        assert isinstance(parsed["checks"], list)
        assert isinstance(parsed["files_scanned"], int)
        assert isinstance(parsed["has_errors"], bool)

    def test_pydantic_v2_features(self):
        """Test Pydantic v2 specific features."""
        check = Check(name="Test Check", status=CheckStatus.PASSED, message="Test message", timestamp=time.time())

        # Test model_dump() method (v2 syntax)
        data = check.model_dump()
        assert isinstance(data, dict)
        assert data["name"] == "Test Check"
        assert data["status"] == "passed"

        # Test model_dump_json() returns JSON string
        json_str = check.model_dump_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["name"] == "Test Check"

        # Test ConfigDict usage
        assert hasattr(check, "model_config")

    def test_model_validation(self):
        """Test that models validate input data."""
        from pydantic import ValidationError

        # Test that required fields are enforced
        with pytest.raises(ValidationError):
            ModelAuditResultModel()  # Missing required fields

        # Test that invalid data is caught
        with pytest.raises(ValidationError):
            Check(
                name="Test",
                status="invalid_status",  # Should be passed/failed/skipped
                message="Test",
                timestamp="not_a_number",  # Should be float
            )
