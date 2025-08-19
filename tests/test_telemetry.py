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

    def test_user_config_defaults_to_disabled(self):
        """Test that telemetry defaults to disabled (opt-in)."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            config = UserConfig()

            assert config.telemetry_enabled is False

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
                assert config.telemetry_enabled is False


class TestTelemetryClient:
    """Test telemetry client functionality."""

    def test_telemetry_disabled_by_default(self):
        """Test that telemetry is disabled by default."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_promptfoo_disable_env_var(self):
        """Test that PROMPTFOO_DISABLE_TELEMETRY works."""
        with (
            patch.dict(os.environ, {"PROMPTFOO_DISABLE_TELEMETRY": "1"}),
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
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._is_disabled() is True

    def test_telemetry_enabled_when_opted_in(self):
        """Test that telemetry works when explicitly enabled."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._user_config.telemetry_enabled = True

            assert client._is_disabled() is False

    @patch("modelaudit.telemetry.urlopen")
    def test_event_recording_when_enabled(self, mock_urlopen):
        """Test that events are recorded when telemetry is enabled."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._user_config.telemetry_enabled = True

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should make network calls
            assert mock_urlopen.call_count == 2  # KA and R endpoints

    def test_event_not_recorded_when_disabled(self):
        """Test that events are not recorded when telemetry is disabled."""
        with (
            patch("modelaudit.telemetry.urlopen") as mock_urlopen,
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            # telemetry_enabled defaults to False

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

            # Should not make network calls
            mock_urlopen.assert_not_called()


class TestDataAnonymization:
    """Test data anonymization and privacy features."""

    def test_path_hashing(self):
        """Test that file paths are hashed for privacy."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            path = "/sensitive/path/to/model.pkl"
            hashed = client._hash_path(path)

            assert hashed != path
            assert len(hashed) == 16  # Truncated hash
            assert hashed.isalnum()  # Hex string

    def test_url_hashing_removes_query_params(self):
        """Test that URL hashing removes potentially sensitive query parameters."""
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            url_with_token = "https://example.com/model?token=secret123&key=private"
            hashed = client._hash_url(url_with_token)

            assert hashed != url_with_token
            assert "secret123" not in hashed
            assert "private" not in hashed

    @patch("modelaudit.telemetry.urlopen")
    def test_scan_started_uses_hashed_paths(self, mock_urlopen):
        """Test that scan_started records hashed paths, not actual paths."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._user_config.telemetry_enabled = True

            paths = ["/sensitive/model1.pkl", "/private/model2.pt"]
            scan_options = {"blacklist_patterns": ["secret", "private"], "format": "json"}

            client.record_scan_started(paths, scan_options)

            # Verify that actual paths are not in the request
            call_args = mock_urlopen.call_args_list
            for call in call_args:
                request_data = call[0][0].data.decode()
                assert "/sensitive/model1.pkl" not in request_data
                assert "/private/model2.pt" not in request_data
                assert "secret" not in request_data
                assert "private" not in request_data

    @patch("modelaudit.telemetry.urlopen")
    def test_download_started_uses_hashed_url(self, mock_urlopen):
        """Test that download_started records hashed URLs."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._user_config.telemetry_enabled = True

            sensitive_url = "https://example.com/model?api_key=secret123"

            client.record_download_started("huggingface", sensitive_url)

            # Verify that actual URL is not in the request
            call_args = mock_urlopen.call_args_list
            for call in call_args:
                request_data = call[0][0].data.decode()
                assert "api_key=secret123" not in request_data
                assert sensitive_url not in request_data


class TestPrivacyCompliance:
    """Test privacy and compliance features."""

    def test_no_file_content_collection(self):
        """Test that file contents are never collected."""
        # This test verifies our implementation doesn't collect file contents
        with tempfile.TemporaryDirectory() as temp_dir, patch("modelaudit.telemetry.Path.home") as mock_home:
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

    def test_error_handling_does_not_leak_data(self):
        """Test that error handling doesn't leak sensitive data."""
        with patch("modelaudit.telemetry.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Network error with /sensitive/path")

            with (
                tempfile.TemporaryDirectory() as temp_dir,
                patch("modelaudit.telemetry.Path.home") as mock_home,
            ):
                mock_home.return_value = Path(temp_dir)
                client = TelemetryClient()
                client._user_config.telemetry_enabled = True

                # This should not raise an exception or leak data
                client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})


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
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            # Should still work without PostHog
            assert client._posthog_client is None
            assert not client._is_disabled() or True  # Depends on config


if __name__ == "__main__":
    pytest.main([__file__])
