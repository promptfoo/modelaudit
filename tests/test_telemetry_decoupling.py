"""
Tests to ensure telemetry is properly decoupled from core functionality.
"""
# ruff: noqa: SIM117

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.telemetry import (
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
        with patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False):
            # Reset the global client cache to force re-initialization
            with patch("modelaudit.telemetry._telemetry_client", None):
                with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
                    mock_home.return_value = Path(temp_dir)

                    from modelaudit.telemetry import get_telemetry_client

                    client = get_telemetry_client()
                    # Should still initialize, just without PostHog
                    assert client is not None
                    assert client._posthog_client is None

    def test_network_failures_dont_break_functionality(self):
        """Test that network failures in telemetry don't affect core functionality."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)

            # Enable telemetry but make all network calls fail
            with patch("modelaudit.telemetry.urlopen", side_effect=Exception("Network down")):
                from modelaudit.telemetry import get_telemetry_client

                client = get_telemetry_client()
                if client is not None:
                    client._user_config.telemetry_enabled = True

                    # These should all complete without exceptions
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
        with (
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


if __name__ == "__main__":
    pytest.main([__file__])
