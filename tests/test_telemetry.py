"""
Comprehensive tests for ModelAudit telemetry system.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.telemetry import (
    TelemetryClient,
    TelemetryEvent,
    UserConfig,
    get_telemetry_client,
    record_event,
    record_scan_started,
)


class TestUserConfig:
    """Test user configuration management."""

    def test_user_config_creates_user_id(self):
        """Test that user config generates a UUID."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".modelaudit" / "user_config.json"

            with patch("modelaudit.telemetry.Path.home") as mock_home:
                mock_home.return_value = Path(temp_dir)
                config = UserConfig()

                assert config.user_id
                assert len(config.user_id) == 36  # UUID length
                assert config_file.exists()

    def test_user_config_defaults_to_enabled(self):
        """Test that telemetry defaults to enabled (opt-out model)."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            config = UserConfig()

            assert config.telemetry_enabled is True

    def test_user_config_persists_settings(self):
        """Test that settings are persisted to file."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)

            config1 = UserConfig()
            config1.telemetry_enabled = True
            config1.email = "test@example.com"

            # Create new instance to test persistence
            config2 = UserConfig()
            assert config2.telemetry_enabled is True
            assert config2.email == "test@example.com"

    def test_user_config_handles_corrupted_file(self):
        """Test that corrupted config files are handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".modelaudit" / "user_config.json"
            config_file.parent.mkdir()
            config_file.write_text("invalid json{")

            with patch("modelaudit.telemetry.Path.home") as mock_home:
                mock_home.return_value = Path(temp_dir)
                config = UserConfig()

                # Should create new config despite corrupted file
                assert config.user_id
                # Default to enabled (opt-out model)
                assert config.telemetry_enabled is True


class TestTelemetryClient:
    """Test telemetry client functionality."""

    def test_telemetry_enabled_by_default_in_production(self):
        """Test that telemetry is enabled by default in production (non-editable install)."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),  # Simulate production
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be enabled by default in production
            assert client._is_disabled() is False

    def test_telemetry_disabled_in_development(self):
        """Test that telemetry is disabled by default in development (editable install)."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", True),  # Simulate development
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_DEV": "",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be disabled by default in development
            assert client._is_disabled() is True

    def test_telemetry_can_be_enabled_in_development(self):
        """Test that telemetry can be explicitly enabled in development."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", True),  # Simulate development
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_DEV": "1",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Telemetry should be enabled when explicitly opted in during development
            assert client._is_disabled() is False

    def test_promptfoo_disable_env_var(self):
        """Test that PROMPTFOO_DISABLE_TELEMETRY works."""
        with (
            patch.dict(os.environ, {"PROMPTFOO_DISABLE_TELEMETRY": "1"}),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_ci_environment_disables_telemetry(self):
        """Test that CI environment disables telemetry."""
        with (
            patch.dict(os.environ, {"CI": "1"}),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_telemetry_can_be_disabled_via_config(self):
        """Test that telemetry can be disabled via user config."""
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
            client = TelemetryClient()
            # Explicitly disable via config
            client._user_config.telemetry_enabled = False

            assert client._is_disabled() is True

    def test_event_recording_when_enabled(self):
        """Test that events are recorded when telemetry is enabled."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should call PostHog capture
            mock_posthog.capture.assert_called_once()
            mock_posthog.flush.assert_called()

    def test_event_not_recorded_when_disabled(self):
        """Test that events are not recorded when telemetry is disabled."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            # Explicitly disable telemetry
            client._user_config.telemetry_enabled = False

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should not call PostHog
            mock_posthog.capture.assert_not_called()


class TestDataHandling:
    """Test data handling and sanitization."""

    def test_error_sanitization(self):
        """Test that error messages are properly sanitized."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Test that paths are removed
            error_with_path = "File not found: /home/user/secret/model.pkl"
            sanitized = client._sanitize_error(error_with_path)
            assert "/home/user" not in sanitized
            assert "[PATH]" in sanitized

            # Test that URLs are removed
            error_with_url = "Failed to fetch https://api.example.com/models?key=secret"
            sanitized = client._sanitize_error(error_with_url)
            assert "api.example.com" not in sanitized
            assert "[URL]" in sanitized

            # Test truncation
            long_error = "x" * 200
            sanitized = client._sanitize_error(long_error)
            assert len(sanitized) <= 100

    def test_model_name_extraction(self):
        """Test model name extraction from various path formats."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # HuggingFace URL
            hf_url = "https://huggingface.co/meta-llama/Llama-2-7b/blob/main/model.pkl"
            assert client._extract_model_name(hf_url) == "meta-llama/Llama-2-7b"

            # HuggingFace shorthand
            hf_short = "hf://meta-llama/Llama-2-7b"
            assert client._extract_model_name(hf_short) == "meta-llama/Llama-2-7b"

            # Local path
            local_path = "/home/user/models/my_model.pkl"
            assert client._extract_model_name(local_path) == "my_model.pkl"


class TestPrivacyCompliance:
    """Test privacy and compliance features."""

    def test_no_file_content_collection(self):
        """Test that file contents are never collected."""
        # This test verifies our implementation doesn't collect file contents
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Inspect all record methods to ensure no file content collection
            methods_to_check = [
                "record_scan_started",
                "record_file_type_detected",
                "record_scanner_used",
                "record_issue_found",
            ]

            for method_name in methods_to_check:
                method = getattr(client, method_name)
                # Method signatures should not include content parameters
                assert "content" not in str(method.__annotations__)
                assert "data" not in str(method.__annotations__)


class TestConvenienceFunctions:
    """Test convenience functions for telemetry."""

    @patch("modelaudit.telemetry.get_telemetry_client")
    def test_record_event_function(self, mock_get_client):
        """Test the record_event convenience function."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

        mock_client.record_event.assert_called_once_with(TelemetryEvent.COMMAND_USED, {"command": "test"})

    @patch("modelaudit.telemetry.get_telemetry_client")
    def test_record_scan_started_function(self, mock_get_client):
        """Test the record_scan_started convenience function."""
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        paths = ["test.pkl"]
        options = {"format": "json"}

        record_scan_started(paths, options)

        mock_client.record_scan_started.assert_called_once_with(paths, options)


class TestTelemetryIntegration:
    """Test telemetry integration points."""

    def test_global_client_singleton(self):
        """Test that get_telemetry_client returns same instance."""
        client1 = get_telemetry_client()
        client2 = get_telemetry_client()

        assert client1 is client2

    def test_posthog_import_failure_handling(self):
        """Test that missing PostHog dependency is handled gracefully."""
        with (
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Should still work without PostHog
            assert client._posthog_client is None


if __name__ == "__main__":
    pytest.main([__file__])
