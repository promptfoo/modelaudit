"""Tests for Pydantic models that match current JSON format."""

import json
from typing import Any, cast

import pytest
from pydantic import ValidationError

# Ensure models are rebuilt for forward references
from modelaudit.models import (
    AssetModel,
    ModelAuditResultModel,
    create_audit_result_model,
    rebuild_models,
)
from modelaudit.scanners.base import Check, CheckStatus, Issue, IssueSeverity

rebuild_models()


@pytest.fixture
def result_payload() -> dict[str, Any]:
    """Literal required fields, with fresh mutable values for each test."""
    return {
        "bytes_scanned": 100,
        "issues": [],
        "checks": [],
        "files_scanned": 1,
        "assets": [],
        "has_errors": False,
        "scanner_names": ["pickle"],
        "file_metadata": {},
        "start_time": 1234567890.0,
        "duration": 1.0,
        "total_checks": 1,
        "passed_checks": 1,
        "failed_checks": 0,
    }


class TestPydanticModels:
    """Test Pydantic model functionality for current JSON format."""

    def test_issue_model_creation(self) -> None:
        """Test Issue creation and serialization."""
        timestamp = 1234567890.0
        issue = Issue(
            message="Test issue",
            severity=IssueSeverity.WARNING,
            location="/path/to/file.pkl",
            details={"key": "value"},
            timestamp=timestamp,
            why="This is why it's a problem",
            type=None,
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

    @pytest.mark.parametrize("status", [CheckStatus.FAILED, CheckStatus.PASSED], ids=["failed-rich", "passed-nullable"])
    def test_check_model_creation(self, status: CheckStatus) -> None:
        """Test Check creation and serialization."""
        timestamp = 1234567890.0
        failed = status == CheckStatus.FAILED
        check = Check(
            name="Test Check",
            status=status,
            message="Check failed" if failed else "Test message",
            severity=IssueSeverity.CRITICAL if failed else None,
            location="/path/to/file.pkl" if failed else None,
            details={"error": "details"} if failed else {},
            timestamp=timestamp,
            why="Explanation of failure" if failed else None,
        )

        assert check.name == "Test Check"
        assert check.status == status
        assert check.message == ("Check failed" if failed else "Test message")
        assert check.severity == (IssueSeverity.CRITICAL if failed else None)
        assert check.location == ("/path/to/file.pkl" if failed else None)
        assert check.details == ({"error": "details"} if failed else {})
        assert check.timestamp == timestamp
        assert check.why == ("Explanation of failure" if failed else None)

        data = check.model_dump()
        assert isinstance(data, dict)
        assert data["name"] == "Test Check"
        assert data["status"] == ("failed" if failed else "passed")
        json_str = check.model_dump_json()
        assert isinstance(json_str, str)
        assert json.loads(json_str)["name"] == "Test Check"
        assert hasattr(check, "model_config")

    def test_model_audit_result_creation(self, result_payload: dict[str, Any]) -> None:
        """Test ModelAuditResultModel creation."""
        result_payload.update(
            bytes_scanned=1000,
            scanner_names=["test_scanner"],
            duration=1.5,
            total_checks=5,
            passed_checks=5,
        )
        result = ModelAuditResultModel(**result_payload)

        assert result.bytes_scanned == 1000
        assert result.files_scanned == 1
        assert result.has_errors is False
        assert result.scanner_names == ["test_scanner"]
        assert result.duration == 1.5
        assert result.total_checks == 5

    def test_create_audit_result_model(self, result_payload: dict[str, Any]) -> None:
        """Test creating ModelAuditResultModel from aggregated results."""
        result_payload.update(
            {
                "bytes_scanned": 2000,
                "issues": [
                    {
                        "message": "Critical issue",
                        "severity": "critical",
                        "location": "/path/to/file1.pkl",
                        "details": {},
                        "timestamp": 1234567890.0,
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
                        "timestamp": 1234567890.0,
                    }
                ],
                "files_scanned": 2,
                "assets": [{"path": "test.pkl", "type": "pickle", "size": 100}],
                "has_errors": True,
                "passed_checks": 0,
                "failed_checks": 1,
            }
        )

        model = create_audit_result_model(result_payload)

        assert isinstance(model, ModelAuditResultModel)
        assert model.bytes_scanned == 2000
        assert len(model.issues) == 1
        assert len(model.checks) == 1
        assert model.files_scanned == 2
        assert len(model.assets) == 1
        assert model.has_errors is True
        assert model.scanner_names == ["pickle"]

    def test_json_serialization_matches_format(self, result_payload: dict[str, Any]) -> None:
        """Test that model JSON serialization matches expected format."""
        result_payload.update(
            issues=[
                Issue(
                    message="Test issue",
                    severity=IssueSeverity.WARNING,
                    timestamp=1234567890.0,
                    location=None,
                    why=None,
                    type=None,
                )
            ],
            checks=[
                Check(
                    name="Test Check",
                    status=CheckStatus.PASSED,
                    message="Check passed",
                    timestamp=1234567890.0,
                    severity=None,
                    location=None,
                    why=None,
                )
            ],
            assets=[AssetModel(path="test.pkl", type="pickle", size=None, tensors=None, keys=None, contents=None)],
        )

        model = ModelAuditResultModel(**result_payload)

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

    def test_model_validation(self) -> None:
        """Test that models validate input data."""
        # Test that required fields are enforced
        with pytest.raises(ValidationError):
            ModelAuditResultModel()  # type: ignore[call-arg]  # Missing required fields - intentionally testing validation

    @pytest.mark.parametrize(
        ("status", "timestamp", "invalid_field"),
        [("invalid_status", 1234567890.0, "status"), (CheckStatus.PASSED, "not_a_number", "timestamp")],
        ids=["invalid-status", "invalid-timestamp"],
    )
    def test_check_validation(self, status: str, timestamp: float | str, invalid_field: str) -> None:
        with pytest.raises(ValidationError) as error:
            Check(
                name="Test",
                status=cast(CheckStatus, status),
                message="Test",
                timestamp=cast(float, timestamp),
                severity=None,
                location=None,
                why=None,
            )
        assert error.value.errors()[0]["loc"] == (invalid_field,)
