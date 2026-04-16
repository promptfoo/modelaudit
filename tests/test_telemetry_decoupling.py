"""
Tests to ensure telemetry is properly decoupled from core functionality.
"""
# ruff: noqa: SIM117

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.telemetry import (
    TelemetryClient,
    TelemetryEvent,
    disable_telemetry,
    enable_telemetry,
    flush_telemetry,
    is_telemetry_available,
    is_telemetry_enabled,
    record_command_used,
    record_event,
    record_feature_used,
    record_file_type_detected,
    record_issue_found,
    record_scanner_used,
    safe_telemetry,
    telemetry_context,
)


class TestTelemetryDecoupling:
    """Test that telemetry failures don't break core functionality."""

    def test_safe_telemetry_decorator_handles_exceptions(self):
        """Test that safe_telemetry decorator catches all exceptions."""

        @safe_telemetry
        def failing_function():
            raise Exception("This should not propagate")

        # Should not raise an exception
        result = failing_function()
        assert result is None

    def test_telemetry_context_handles_exceptions(self):
        """Test that telemetry_context catches all exceptions."""
        exception_occurred = False

        try:
            with telemetry_context():
                raise Exception("This should not propagate")
        except Exception:
            exception_occurred = True

        # Exception should not have propagated
        assert not exception_occurred

    def test_all_record_functions_safe_when_client_fails(self):
        """Test that all telemetry record functions are safe when client initialization fails."""
        # Mock get_telemetry_client to return None (simulating initialization failure)
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            # All these should complete without raising exceptions
            record_event(TelemetryEvent.COMMAND_USED, {"test": "data"})
            record_command_used("test_command", duration=1.0, extra="param")
            record_feature_used("test_feature", enabled=True)
            record_scanner_used("test_scanner", "pkl", 0.5)
            record_file_type_detected("/path/to/file.pkl", "pickle", 0.9)
            record_issue_found("malicious_code", "critical", "test_scanner")
            flush_telemetry()

    def test_telemetry_functions_safe_when_client_raises_exception(self):
        """Test that telemetry functions are safe when client methods raise exceptions."""
        mock_client = MagicMock()
        mock_client.record_event.side_effect = Exception("Network error")
        mock_client.record_command_used.side_effect = Exception("Disk error")

        with patch("modelaudit.telemetry.get_telemetry_client", return_value=mock_client):
            # All these should complete without raising exceptions
            record_event(TelemetryEvent.COMMAND_USED, {"test": "data"})
            record_command_used("test_command")

    def test_is_telemetry_available_handles_failures(self):
        """Test that is_telemetry_available gracefully handles client failures."""
        # Test when client initialization fails
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            assert is_telemetry_available() is False

        # Test when client raises exception
        with patch("modelaudit.telemetry.get_telemetry_client", side_effect=Exception("Init error")):
            assert is_telemetry_available() is False

    def test_is_telemetry_enabled_handles_failures(self):
        """Test that is_telemetry_enabled gracefully handles client failures."""
        # Test when client initialization fails
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            assert is_telemetry_enabled() is False

        # Test when client raises exception
        with patch("modelaudit.telemetry.get_telemetry_client", side_effect=Exception("Init error")):
            assert is_telemetry_enabled() is False

    def test_enable_disable_telemetry_safe_when_client_fails(self):
        """Test that enable/disable telemetry functions are safe when client fails."""
        with patch("modelaudit.telemetry.get_telemetry_client", return_value=None):
            # Should not raise exceptions
            enable_telemetry()
            disable_telemetry()

    def test_telemetry_client_initialization_failure_handled(self):
        """Test that TelemetryClient initialization failures are handled gracefully."""
        # Reset the global client cache
        with patch("modelaudit.telemetry._telemetry_client", None):
            with patch("modelaudit.telemetry.TelemetryClient", side_effect=Exception("Init failed")):
                from modelaudit.telemetry import get_telemetry_client

                client = get_telemetry_client()
                assert client is None

    @patch("modelaudit.telemetry.UserConfig")
    def test_user_config_failure_handled(self, mock_user_config):
        """Test that UserConfig initialization failures are handled gracefully."""
        mock_user_config.side_effect = Exception("Config file corrupted")

        # Reset the global client cache
        with patch("modelaudit.telemetry._telemetry_client", None):
            with patch("modelaudit.telemetry.TelemetryClient", side_effect=Exception("Init failed")):
                from modelaudit.telemetry import get_telemetry_client

                client = get_telemetry_client()
                assert client is None

    def test_posthog_import_failure_handled(self):
        """Test that PostHog import failures don't break telemetry initialization."""
        with (
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),  # Simulate production
            patch("modelaudit.telemetry._telemetry_client", None),  # Reset client cache
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)

            from modelaudit.telemetry import get_telemetry_client

            client = get_telemetry_client()
            # Should still initialize, just without PostHog
            assert client is not None
            assert client._posthog_client is None

    def test_network_failures_dont_break_functionality(self):
        """Test that network failures in telemetry don't affect core functionality."""
        mock_posthog = MagicMock()
        mock_posthog.capture.side_effect = Exception("Network down")
        mock_posthog.flush.side_effect = Exception("Network down")

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)

            from modelaudit.telemetry import get_telemetry_client

            client = get_telemetry_client()
            if client is not None:
                client._posthog_client = mock_posthog
                client._user_config.telemetry_enabled = True

                # These should all complete without exceptions (even with network failures)
                record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})
                record_command_used("test")
                flush_telemetry()

    def test_file_system_failures_handled(self):
        """Test that file system failures don't break telemetry initialization."""
        # Mock Path.home() to return a non-existent directory that can't be created
        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path("/non/existent/readonly/path")

            # This might fail but should be handled gracefully
            from modelaudit.telemetry import get_telemetry_client

            # Should either return a client or None, but not raise an exception
            try:
                client = get_telemetry_client()
                # If it succeeds, telemetry should work in degraded mode
                if client is not None:
                    record_command_used("test")
            except PermissionError:
                # If it fails, that's also acceptable - the point is it doesn't crash
                pass


class TestTelemetryFunctionalityWhenWorking:
    """Test that telemetry still works correctly when everything is functioning."""

    def test_telemetry_works_when_enabled_and_available(self):
        """Test that telemetry actually works when properly configured."""
        mock_posthog = MagicMock()
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),  # Simulate production
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)

            from modelaudit.telemetry import get_telemetry_client

            client = get_telemetry_client()
            assert client is not None

            # Enable telemetry
            client._user_config.telemetry_enabled = True
            assert is_telemetry_enabled() is True
            assert is_telemetry_available() is True

    def test_safe_decorator_passes_through_return_values(self):
        """Test that safe_telemetry decorator doesn't interfere with return values."""

        @safe_telemetry
        def working_function():
            return "success"

        result = working_function()
        assert result == "success"

    def test_telemetry_context_allows_normal_execution(self):
        """Test that telemetry_context allows normal execution when no errors occur."""
        result = None

        with telemetry_context():
            result = "executed successfully"

        assert result == "executed successfully"

    def test_record_issue_found_redacts_sensitive_data(self, tmp_path: Path) -> None:
        """Issue telemetry should not copy free-form scanner messages into analytics fields."""
        captured: dict[str, object] = {}

        def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
            captured["event"] = event
            captured["properties"] = properties or {}

        sensitive_path = tmp_path / "private-model.pkl"
        another_sensitive_path = tmp_path / "secrets" / "weights.bin"
        message = (
            f"Unsafe pickle found in {sensitive_path}; "
            f"secondary artifact at {another_sensitive_path}; "
            "downloaded from https://example.com/model?token=secret&api_key=AKIA1234567890; "
            "Authorization: Bearer very-secret-token"
        )

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            client = TelemetryClient()
            client.record_event = capture_event  # type: ignore[method-assign]
            client.record_issue_found(
                message,
                "critical",
                "pickle",
                file_path=str(sensitive_path),
            )

        assert captured["event"] == TelemetryEvent.ISSUE_FOUND
        properties = captured["properties"]
        assert isinstance(properties, dict)
        assert properties["issue_type"] == "unknown_issue"
        assert "issue_message" not in properties
        serialized = json.dumps(properties)
        assert str(sensitive_path) not in serialized
        assert str(another_sensitive_path) not in serialized
        assert "token=secret" not in serialized
        assert "api_key=AKIA1234567890" not in serialized
        assert "Bearer very-secret-token" not in serialized

    def test_record_issue_found_filters_token_like_strings(self, tmp_path: Path) -> None:
        """Slug-like filenames and tokens must not be treated as stable issue IDs."""
        captured: dict[str, object] = {}

        def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
            captured["event"] = event
            captured["properties"] = properties or {}

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            client = TelemetryClient()
            client.record_event = capture_event  # type: ignore[method-assign]
            client.record_issue_found("private-model.pkl", "critical", "pickle")
            filename_properties = captured["properties"]
            client.record_issue_found("secret-token-abc123", "critical", "pickle")
            slug_token_properties = captured["properties"]
            client.record_issue_found("sk_live_1234567890abcdef", "critical", "pickle")
            token_properties = captured["properties"]
            client.record_issue_found(
                "legacy message mentions CVE-2025-23304",
                "critical",
                "nemo",
                issue_message="legacy message mentions CVE-2025-23304",
            )
            cve_properties = captured["properties"]
            client.record_issue_found(
                "legacy message mentions S1101",
                "critical",
                "nemo",
                issue_message="legacy message mentions S1101",
            )
            rule_properties = captured["properties"]
            client.record_issue_found("pickle_dangerous_global", "critical", "pickle")
            structured_properties = captured["properties"]

        assert isinstance(filename_properties, dict)
        assert filename_properties["issue_type"] == "unknown_issue"
        assert isinstance(slug_token_properties, dict)
        assert slug_token_properties["issue_type"] == "unknown_issue"
        assert isinstance(token_properties, dict)
        assert token_properties["issue_type"] == "unknown_issue"
        assert isinstance(cve_properties, dict)
        assert cve_properties["issue_type"] == "cve:CVE-2025-23304"
        assert "legacy message" not in json.dumps(cve_properties)
        assert isinstance(rule_properties, dict)
        assert rule_properties["issue_type"] == "rule:S1101"
        assert "legacy message" not in json.dumps(rule_properties)
        assert isinstance(structured_properties, dict)
        assert structured_properties["issue_type"] == "pickle_dangerous_global"
        serialized = json.dumps(
            {
                "filename": filename_properties,
                "slug_token": slug_token_properties,
                "token": token_properties,
                "structured": structured_properties,
            }
        )
        assert "private-model.pkl" not in serialized
        assert "secret-token-abc123" not in serialized
        assert "sk_live_1234567890abcdef" not in serialized

    def test_scan_completed_uses_rule_identifiers_not_issue_messages(self, tmp_path: Path) -> None:
        """Completed-scan telemetry should count stable rule IDs and omit raw issue text."""
        captured: dict[str, object] = {}

        def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
            captured["event"] = event
            captured["properties"] = properties or {}

        sensitive_path = tmp_path / "secret-model.nemo"
        raw_message = f"CVE-2025-23304: dangerous target in {sensitive_path} https://example.com/?token=secret"

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            client = TelemetryClient()
            client.record_event = capture_event  # type: ignore[method-assign]
            client.record_scan_completed(
                0.1,
                {
                    "files_scanned": 1,
                    "scanner_names": ["nemo"],
                    "issues": [
                        {
                            "message": raw_message,
                            "severity": "critical",
                            "location": str(sensitive_path),
                            "type": "nemo_check",
                            "rule_code": "S1101",
                            "details": {"cve_id": "CVE-2025-23304"},
                        }
                    ],
                    "assets": [],
                },
            )

        assert captured["event"] == TelemetryEvent.SCAN_COMPLETED
        properties = captured["properties"]
        assert isinstance(properties, dict)
        assert properties["issue_types"] == {"rule:S1101": 1}
        assert properties["issue_details"][0]["type"] == "rule:S1101"
        serialized = json.dumps(properties)
        assert raw_message not in serialized
        assert str(sensitive_path) not in serialized
        assert "token=secret" not in serialized

    def test_scan_completed_handles_missing_or_malformed_issue_metadata(self, tmp_path: Path) -> None:
        """Completed-scan telemetry should handle incomplete issue metadata without raw text."""
        captured: dict[str, object] = {}

        def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
            captured["event"] = event
            captured["properties"] = properties or {}

        sensitive_path = tmp_path / "private-artifact.nemo"
        raw_message = f"Legacy finding in {sensitive_path} token=topsecret"

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            client = TelemetryClient()
            client.record_event = capture_event  # type: ignore[method-assign]
            client.record_scan_completed(
                0.1,
                {
                    "files_scanned": 1,
                    "scanner_names": ["nemo"],
                    "issues": [
                        {"message": raw_message, "severity": "critical"},
                        {"message": raw_message, "severity": "high", "rule_code": None},
                        {"message": raw_message, "severity": "medium", "rule_code": ""},
                        {"message": raw_message, "severity": "low", "cve_id": None},
                        {"message": raw_message, "severity": "low", "cve_id": ""},
                    ],
                    "assets": [],
                },
            )

        assert captured["event"] == TelemetryEvent.SCAN_COMPLETED
        properties = captured["properties"]
        assert isinstance(properties, dict)
        assert properties["issue_types"] == {"unknown_issue": 5}
        serialized = json.dumps(properties)
        assert raw_message not in serialized
        assert str(sensitive_path) not in serialized
        assert "token=topsecret" not in serialized

    @pytest.mark.parametrize(
        "token_messages",
        [
            [
                "private-model.pkl",
                "secret-token-abc123",
                "sk_live_1234567890abcdef",
            ],
            [
                "AKIAIOSFODNN7EXAMPLE",
                "ghp_1234567890abcdef1234567890abcdef1234",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            ],
        ],
    )
    def test_scan_completed_rejects_token_shaped_legacy_messages(
        self, tmp_path: Path, token_messages: list[str]
    ) -> None:
        """Message-only telemetry can expose rule/CVE tokens, not arbitrary slug-like text."""
        captured: dict[str, object] = {}

        def capture_event(event: TelemetryEvent, properties: dict[str, object] | None = None) -> None:
            captured["event"] = event
            captured["properties"] = properties or {}

        with patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = tmp_path
            client = TelemetryClient()
            client.record_event = capture_event  # type: ignore[method-assign]
            client.record_scan_completed(
                0.1,
                {
                    "files_scanned": 1,
                    "scanner_names": ["pickle"],
                    "issues": [
                        *[{"message": message, "severity": "critical"} for message in token_messages],
                        {"message": "CVE-2025-23304 in sanitized legacy text", "severity": "critical"},
                        {"message": "S1101 in sanitized legacy text", "severity": "critical"},
                    ],
                    "assets": [],
                },
            )

        assert captured["event"] == TelemetryEvent.SCAN_COMPLETED
        properties = captured["properties"]
        assert isinstance(properties, dict)
        assert properties["issue_types"] == {
            "unknown_issue": len(token_messages),
            "cve:CVE-2025-23304": 1,
            "rule:S1101": 1,
        }
        serialized = json.dumps(properties)
        for message in token_messages:
            assert message not in serialized


if __name__ == "__main__":
    pytest.main([__file__])
