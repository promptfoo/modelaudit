"""
Comprehensive tests for ModelAudit telemetry system.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.telemetry import (
    TelemetryClient,
    TelemetryEvent,
    UserConfig,
    enable_telemetry,
    get_telemetry_client,
    is_telemetry_available,
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
            mock_posthog.flush.assert_not_called()

    def test_event_recording_can_flush_immediately_when_configured(self):
        """Immediate flush can be enabled for low-latency delivery."""
        mock_posthog = MagicMock()

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch.dict(
                os.environ,
                {
                    "CI": "",
                    "IS_TESTING": "",
                    "PROMPTFOO_DISABLE_TELEMETRY": "",
                    "NO_ANALYTICS": "",
                    "MODELAUDIT_TELEMETRY_FLUSH_IMMEDIATELY": "1",
                },
                clear=False,
            ),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            client.record_event(TelemetryEvent.COMMAND_USED, {"command": "test"})

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

    def test_scan_completed_uses_top_level_results_schema(self):
        """Test that scan completion telemetry aggregates from top-level issues/assets."""
        mock_posthog = MagicMock()

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
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            results = {
                "files_scanned": 2,
                "scanner_names": ["pickle", "zip"],
                "assets": [
                    {"path": "/tmp/a.pkl", "type": "pickle"},
                    {"path": "/tmp/b.zip", "type": "zip"},
                ],
                "issues": [
                    {"message": "Issue A", "severity": "critical", "location": "/tmp/a.pkl"},
                    {"message": "Issue B", "severity": "warning", "location": "/tmp/b.zip"},
                    {
                        "type": "pickle_dangerous_global",
                        "message": "Legacy message should not be used when type exists",
                        "severity": "info",
                        "location": "/tmp/a.pkl",
                    },
                ],
            }

            client.record_scan_completed(1.5, results)
            properties = mock_posthog.capture.call_args.kwargs["properties"]

            assert properties["total_files"] == 2
            assert properties["total_issues"] == 3
            assert properties["issue_types"]["Issue A"] == 1
            assert properties["issue_types"]["Issue B"] == 1
            assert properties["issue_types"]["pickle_dangerous_global"] == 1
            assert "Legacy message should not be used when type exists" not in properties["issue_types"]
            assert properties["issue_severities"]["critical"] == 1
            assert properties["issue_severities"]["warning"] == 1
            assert properties["issue_severities"]["info"] == 1
            assert properties["file_types"]["pickle"] == 1
            assert properties["file_types"]["zip"] == 1
            assert sorted(properties["scanners_used"]) == ["pickle", "zip"]
            assert properties["files_scanned"] == ["/tmp/a.pkl", "/tmp/b.zip"]
            canonical_issue = next(
                detail for detail in properties["issue_details"] if detail["type"] == "pickle_dangerous_global"
            )
            assert canonical_issue["file_path"] == "/tmp/a.pkl"
            assert canonical_issue["model_name"] == "a.pkl"

    def test_scan_started_includes_per_path_fields(self):
        """Scan started events include per-path arrays and model names."""
        mock_posthog = MagicMock()

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
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            paths = ["/tmp/model.pkl", "hf://meta-llama/Llama-2-7b"]
            client.record_scan_started(paths, {"format": "json"})

            properties = mock_posthog.capture.call_args.kwargs["properties"]
            assert properties["paths"] == paths
            assert properties["model_names"][0] == "model.pkl"
            assert properties["model_names"][1] == "meta-llama/Llama-2-7b"
            assert properties["source_types"] == ["local", "huggingface"]
            assert properties["path_types"][0] in {"file", "unknown"}
            assert properties["path_types"][1] == "huggingface_shorthand"

    def test_path_and_url_fields_include_raw_and_hashed_values(self):
        """Raw path/URL fields are present along with hashed identifiers."""
        mock_posthog = MagicMock()

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
            client._posthog_client = mock_posthog
            client._user_config.telemetry_enabled = True

            sensitive_path = "/home/user/private/model.pkl"
            sensitive_url = "https://example.com/model.bin?token=secret"

            client.record_file_type_detected(sensitive_path, "pickle")
            file_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert file_props["file_path"] == sensitive_path
            assert file_props["model_name"] == "model.pkl"
            assert "path_identifier" in file_props

            client.record_issue_found("dangerous pattern", "critical", "pickle", sensitive_path)
            issue_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert issue_props["file_path"] == sensitive_path
            assert issue_props["model_name"] == "model.pkl"
            assert "path_identifier" in issue_props

            client.record_download_started("http", sensitive_url)
            download_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert download_props["url"] == sensitive_url
            assert download_props["model_name"] == "model.bin"
            assert "url_identifier" in download_props

            client.record_download_completed("http", 2.0, 2048, sensitive_url)
            completed_props = mock_posthog.capture.call_args.kwargs["properties"]
            assert completed_props["url"] == sensitive_url
            assert completed_props["model_name"] == "model.bin"
            assert "url_identifier" in completed_props

    def test_extract_model_name_strips_query_string_for_http_urls(self):
        """Model name extraction should not include URL query parameters."""
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
        ):
            mock_home.return_value = Path(temp_dir)
            client = TelemetryClient()

            assert client._extract_model_name("https://example.com/model.bin?token=secret") == "model.bin"
            assert client._extract_model_name("https://example.com/model.bin#fragment") == "model.bin"

    def test_telemetry_available_false_when_posthog_unavailable(self):
        """Telemetry should be unavailable when transport client is missing."""
        with (
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", False),
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            tempfile.TemporaryDirectory() as temp_dir,
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
            patch("modelaudit.telemetry._telemetry_client", None),
        ):
            mock_home.return_value = Path(temp_dir)
            assert is_telemetry_available() is False

    def test_enable_telemetry_initializes_transport_for_existing_client(self, tmp_path: Path) -> None:
        """Enabling telemetry should lazily initialize PostHog for an existing client."""
        mock_posthog = MagicMock()

        with (
            patch("modelaudit.telemetry.Path.home") as mock_home,
            patch("modelaudit.telemetry._IS_DEVELOPMENT", False),
            patch("modelaudit.telemetry.POSTHOG_AVAILABLE", True),
            patch("modelaudit.telemetry.Posthog", return_value=mock_posthog),
            patch("modelaudit.telemetry._telemetry_client", None),
            patch.dict(
                os.environ,
                {"CI": "", "IS_TESTING": "", "PROMPTFOO_DISABLE_TELEMETRY": "", "NO_ANALYTICS": ""},
                clear=False,
            ),
        ):
            mock_home.return_value = tmp_path
            config_dir = tmp_path / ".modelaudit"
            config_dir.mkdir()
            (config_dir / "user_config.json").write_text(json.dumps({"telemetry_enabled": False}))

            client = get_telemetry_client()
            assert client is not None
            assert client._posthog_client is None

            enable_telemetry()
            refreshed_client = get_telemetry_client()

            assert refreshed_client is not None
            assert refreshed_client._user_config.telemetry_enabled is True
            assert refreshed_client._posthog_client is mock_posthog
            assert is_telemetry_available() is True


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

    def test_global_client_refreshes_when_runtime_changes(self, tmp_path: Path) -> None:
        """Runtime-sensitive singleton state should refresh between different environments."""
        mock_posthog = MagicMock()
        first_home = tmp_path / "first-home"
        second_home = tmp_path / "second-home"
        first_home.mkdir()
        second_home.mkdir()

        with patch("modelaudit.telemetry._telemetry_client", None):
            with (
                patch("modelaudit.telemetry.Path.home") as mock_home,
                patch.dict(os.environ, {"PROMPTFOO_DISABLE_TELEMETRY": "1"}, clear=False),
            ):
                mock_home.return_value = first_home
                first_client = get_telemetry_client()

            with (
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
                mock_home.return_value = second_home
                refreshed_client = get_telemetry_client()

            assert refreshed_client is not None
            assert refreshed_client is not first_client
            assert refreshed_client._posthog_client is mock_posthog

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

    @patch("modelaudit.core.record_issue_found")
    def test_core_scan_emits_issue_found_telemetry(self, mock_record_issue_found):
        """Core scans should emit issue telemetry for detected findings."""
        from modelaudit.core import scan_model_directory_or_file

        sample = Path(__file__).parent / "assets" / "samples" / "pickles" / "malicious_system_call.pkl"
        result = scan_model_directory_or_file(str(sample))

        assert len(result.issues) > 0
        assert mock_record_issue_found.call_count > 0


if __name__ == "__main__":
    pytest.main([__file__])
